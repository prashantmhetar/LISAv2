##############################################################################################
# WSL2Provider.psm1
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
# Operations :
#
<#
.SYNOPSIS
	PS modules for LISAv2 test automation
	This module provides the test operations on version 2 of the Windows Subsystem of Linux

.PARAMETER
	<Parameters>

.INPUTS

.NOTES
	Creation Date:
	Purpose/Change:

.EXAMPLE
#>
###############################################################################################
using Module ".\TestProvider.psm1"
using Module "..\Libraries\Azure.psm1"

function EnableWindowsOptionalFeatureForced([string] $featureName)
{
	if ((Get-WindowsOptionalFeature -Online -FeatureName $featureName).State `
		-ne "Enabled")
	{
		$result = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart

		if ($result.RestartNeeded -eq $true)
		{
			return "Reboot"
		}
		elseif ((Get-WindowsOptionalFeature -Online -FeatureName $featureName).State `
			-ne "Enabled")
		{
			return "Unsupported"
		}
	}
	return "Enabled"
}

Class WSL2Provider : TestProvider
{
	[string] $DistroFilePath
	[string] $DestinationDistroFilePath
	[object] $session
	[string] $DestinationResourceGroup
	[string] $TestLocation
	[string] $OsVHD
	[string] $VHDUser
	[string] $VHDPassword
	[string] $DistroName
	[string] $server
	[int] $SSHPort
	[object] $PersistentWSLSession = $null
	[object] $PersistentWSLJob = $null
	[string] $launchDistroCommand = ""
	
	WSL2Provider() {
		$this.DistroFilePath = @()
	}

	[void] Initialize($WslConfig) {

		$this.VHDUser = $wslConfig.VHDUserName
		$this.VHDPassword = $wslConfig.VHDPassword
		$this.DistroFilePath = $wslConfig.DistroFilePath
		$this.DestinationDistroFilePath = $wslConfig.DestinationDistroFilePath
		$this.SSHPort = $wslConfig.SSHPort
	}

	#this needs to run through remote session, plink.exe and pscp.exe need to be copied over.
	[bool] IsWSLRunning([string] $distroName, [string] $ipAddress)
	{
		Write-LogInfo "IsWSLRunning check if WSL distribution $distroName is running, IP address $ipAddress can be connected to and PSCP is working."
		$success = $false
		$localPath = "$PWD\Tools\"
		# Assumption of where Windows directory is
		$remotePath = "C:\Windows\Temp\"
		Copy-Item -ToSession $this.Session -Path $localPath -Destination $remotePath -Recurse
		$pscpTestJob = Invoke-Command -AsJob -Session $this.Session -ArgumentList $distroName,$ipAddress,$this.SSHPort,$global:user,$global:password,$remotePath `
			-ScriptBlock `
		{
			param ($distroName,$ipAddress,$port,$user,$password,$remotePath)
			Push-Location -Path $remotePath
			# Note that WSL2 will put the distribution in Stopped state if WSL distribution
			# is idle (ie. no WSL processes) so keeping the process active so that the
			# IP address is valid for tests is needed.
			$process = $null
			#Second WSL process is used for debugging WSL interactively locally only.
			$process2 = Start-Process -FilePath "wsl.exe" -PassThru
			$psi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
			$psi.FileName = "wsl.exe"
			$psi.RedirectStandardOutput = $true
			$psi.RedirectStandardInput = $true
			$psi.UseShellExecute = $false
			$psi.CreateNoWindow = $false
			$process = New-Object -TypeName System.Diagnostics.Process
			$process.StartInfo = $psi
			$process.Start() | Out-Null
			$standardInput = $process.StandardInput
			$standardOutput = $process.StandardOutput
			if ($process.HasExited)
			{
				throw "Unable to start new wsl.exe after killing old one"
			}

			Write-Output "writing service ssh restart"
			$standardInput.Write("`nservice ssh restart`n")
			Write-Output $standardOutput.ReadLine()
			Write-Output "`r"
			$output = & wsl --list --verbose
			$found = $false
			foreach ($line in $output)
			{
				$asciiLine = $line.Replace("`0", "")
				if ($asciiLine -eq "")
				{
					continue
				}
				if ($asciiLine -imatch "^`*.*Running")
				{
					$found = $true
					break
				}
			}
			if (!$found)
			{
				throw "cannot find distribution running in list"
			}

			Write-Output "Setting up host port forwarder in WSL Host"
			netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$ipAddress

			$tries = 0
			$maxTries = 5
			$success = $false
			# Kill the registry ssh key for this remote ip address
			$regPath = "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys"
			Write-Output "regPath $regPath"
			# It may be different than ed25519 but that is currently what is used
			$regValueName = "ssh-ed25519@${port}:$ipAddress"
			$iprop = Get-ItemProperty -Path $regPath -Name $regValueName
			Write-Output "ItemPropertyName $regValueName"
			Write-Output "property $iprop"
			if ($iprop -ne $null)
			{
				Write-Output "Removing item property $iprop"
				Remove-ItemProperty -Force -Path $regPath -Name $regValueName
			}
			# Call plink first because plink takes standard input for the y or n command to store or overwrite the ssh key
			# but pscp does not
			$file = Join-Path -Path $env:TEMP -ChildPath "plinkrawlog"
			Remove-Item -Force $file
			Write-Output "yes" | .\Tools\plink.exe -sshrawlog $file -C -pw $password -P $port $user@$ipAddress exit
			do
			{
				Write-Output "try pscp"
				# Try PSCP
				try
				{
					$file = "pscptest"
					$file = Join-Path -Path $env:TEMP -ChildPath $file
					Set-Content -Path $file -Value "test" -Force
					$rawlog = Join-Path -Path $env:TEMP -ChildPath "sshraw"
					$sshlog = Join-Path -Path $env:TEMP -ChildPath "sshlog"
					$uploadTo = $ipAddress
					Write-Output "test parameters port $port file $file, rawlog $rawlog, uploadTo $uploadTo, ipAddress $ipAddress, $user, $password"
					# Remove old raw log to avoid prompt in pscp
					Remove-Item -Force -Path $rawlog
					Remove-Item -Force -Path $sshlog
					Write-Output "Status of ssh"
					$standardInput.Write("service ssh status`n")
					Write-Output $standardOutput.ReadLine()
					Write-Output "`r`n"
					$pscpProcess = Start-Process -FilePath "$PWD\Tools\pscp.exe" -WorkingDirectory "$PWD" -ArgumentList "-batch -q -sshrawlog $rawlog -v -P $port -pw $password $file $user@${ipAddress}:/home/$user" -PassThru
					$success = $false
					$startTime = Get-Date
					do
					{
						$now = Get-Date
						$cmd = "ls /home/$user/pscptest`n"
						$standardInput.Write($cmd)
						$output = $standardOutput.ReadLine()
						Write-Output "$output"
						if ($output -match "^/home/$user/pscptest")
						{
							Write-Output "pscp successfully copied the file over."
							$success = $true
						}
						elseif ($pscpProcess.HasExited)
						{
							# Restart process
							$startTime = Get-Date
							$pscpProcess = Start-Process -FilePath "$PWD\Tools\pscp.exe" -WorkingDirectory "$PWD" -ArgumentList "-batch -q -l $user -sshrawlog $rawlog -v -P $port -pw $password $file ${ipAddress}:/home/$user" -PassThru
						}
						elseif ((($now - $startTime).TotalSeconds -gt 60))
						{
							Write-Output "Timed out.  pscp not successfully copied over."
							break
						}
						else {
							Write-Output "Continue letting the process run, file not copied over yet: $output."
						}
						Start-Sleep -s 5
					} until ($success)
					if ($success)
					{
						Write-Output "file copied over, kill process and restart service"
						if ($pscpProcess.HasExited)
						{
							Write-Output "Success, pscp process exited successfully"
						}
						else {
							Write-Output "pscp process copied but process did not exit"
							Stop-Process $pscpProcess -Force
							Write-Output "writing service ssh restart"
							$standardInput.Write("`nservice ssh restart`n")
							Write-Output $standardOutput.ReadLine()
							Write-Output "`r`n"
							Start-Sleep -s 5
						}
					}
					else {
						Write-Output "file not copied over, kill process and restart service"
					}
				}
				catch
				{
					$e = $_.Exception
					$line = $_.InvocationInfo.ScriptLineNumber
					$msg = $e.Message
					Write-Output "exception at line number $line, msg $msg"
					Pop-Location
					throw "exception at line number $line, msg $msg"
				}
				if ($success)
				{
					Write-Output "Exiting because pscp succeeded"
					break
				}

				Write-Output "writing service ssh restart"
				$standardInput.Write("`nservice ssh restart`n")
				Write-Output $standardOutput.ReadLine()
				Write-Output "`r`n"
				Start-Sleep -s 5
				$tries++
			} until ($tries -ge $maxTries)
			if ($success)
			{
				Write-Output "Successfully verified in test setup that WSL distribution is running, IP address can be connected to and that pscp is working correctly."
			}
			else
			{
				Write-Output "Did not successfully verify WSL up and running and can be connected to and pscp connected to"
			}
			Pop-Location
		}
		Wait-Job -Job $pscpTestJob -Timeout 60
		#Stop-Job $pscpTestJob 
		$pscpTestOutput = Receive-Job -Job $pscpTestJob -Keep
		#Remove-Job $pscpTestJob -Force
		Write-LogInfo "Result of pscp test: $pscpTestOutput"
		if ($pscpTestOutput -imatch "pscp succeeded")
		{
			$success = $true
		}
		return $success
	}

	[object] DeployVMs([xml] $GlobalConfig, [object] $SetupTypeData, [object] $TestCaseData, [string] $TestLocation, [string] $RGIdentifier, [bool] $UseExistingRG, [string] $ResourceCleanup) {
		$allVMData = @()
		$DeploymentElapsedTime = $null
		try {
			if ($UseExistingRG) {
				Write-LogInfo "Running test against existing resource group: $RGIdentifier"
				$allVMData = Get-AllDeploymentData -ResourceGroups $RGIdentifier
				if (!$allVMData) {
					Write-LogInfo "No VM is found in resource group $RGIdentifier, start to deploy VMs"
				}
			}		
			# if you love me, write comment with explain why you over wrtiting the setuptype and SetupTypeData
			$SetupType = 'OneVMWin'
			$file = Get-ChildItem -Path "$global:WorkingDirectory\XML\VMConfigurations\OneVM.xml"
			$CurrentSetupType = ([xml]( Get-Content -Path $file)).TestSetup
				if ($CurrentSetupType.$SetupType) {
					$SetupTypeData = $CurrentSetupType.$SetupType
				}
				else {
					throw "Did file $SetupType in $file "
				}

			if (!$allVMData) {
				$isAllDeployed = Create-AllResourceGroupDeployments -SetupTypeData $SetupTypeData -TestCaseData $TestCaseData -Distro $RGIdentifier `
					-TestLocation $TestLocation -GlobalConfig $GlobalConfig -TipSessionId $this.TipSessionId -TipCluster $this.TipCluster `
					-UseExistingRG $UseExistingRG -ResourceCleanup $ResourceCleanup

				if ($isAllDeployed[0] -eq "True") {
					$deployedGroups = $isAllDeployed[1]
					$DeploymentElapsedTime = $isAllDeployed[3]
					$allVMData = Get-AllDeploymentData -ResourceGroups $deployedGroups
				} else {
					$ErrorMessage = "One or more deployments failed. " + $isAllDeployed[4]
					Write-LogErr $ErrorMessage
					return @{"VmData" = $null; "Error" = $ErrorMessage}
				}
			}
			# this is needed so WSL VM on host can be sshed from outside network.
			Write-LogInfo "Setting up inBound NAT Rule for port : $($this.SSHPort)"
			$azureLB = Get-AzLoadBalancer -ResourceGroupName $allVMData.ResourceGroupName
			$azureLB | Add-AzLoadBalancerInboundNatRuleConfig -Name "WSLSSHRule" -FrontendIPConfiguration $azureLB.FrontendIpConfigurations[0] `
			-Protocol "Tcp" -FrontendPort $($this.SSHPort) -BackendPort $($this.SSHPort)

			$nicName=(Get-AzNetworkInterface -ResourceGroupName $allVMData.ResourceGroupName ).Name
			$nic = Get-AzNetworkInterface -ResourceGroupName $allVMData.ResourceGroupName -Name $nicName
			$nic.IpConfigurations[0].LoadBalancerInboundNatRules.Add($azureLB.InboundNatRules[2])
			$azureLB | Set-AzLoadBalancer

			Set-AzNetworkInterface -NetworkInterface $nic 
			$cred = Get-Cred -user $this.VHDUser -password $this.VHDPassword
			if ($cred -eq $null)
			{
				Write-LogInfo "Provided VHD WSL credential is invalid, aborting test"
				throw "credential is invalid"
			}

			$wslPip = $allVMData.PublicIP
			Write-LogInfo  "Setting WSLPIP to IP:$wslPip "
			$this.session = $this.CreateNewPSSession($wslPip)
			if ($this.session -eq $null)
			{
				Write-LogInfo "Powershell session is null, aborting"
				throw "Unable to connect to WSL powershell session"
			}
	
			$successState = $this.VerifyWSLSetup($this.session)
			if (-not $successState)
			{
				Write-LogErr "VerifyWSLSetup failed, aborting"
				throw "Correct test failures and restart LISAv2 test for WSLv2."
			}
			
			# Install distribution and enable WSL v2
			$this.DistroName = $this.InstallDistribution($this.server, $this.session)
			if ($this.DistroName -ne "")
			{
				# Get the IP address
				$ipAddress = $this.GetIPAddress($this.session)
				Write-LogInfo "IP address of WSL VM is $ipAddress"
				Add-Member -InputObject $allVMData -MemberType NoteProperty -Name SSHPort -Value $this.SSHPort -Force
			}
		}
		catch {
			Write-LogErr "Exception detected. Source : DeployVMs()"
			$line = $_.InvocationInfo.ScriptLineNumber
			$script_name = ($_.InvocationInfo.ScriptName).Replace($PWD, ".")
			$ErrorMessage = $_.Exception.Message
			Write-LogErr "EXCEPTION : $ErrorMessage"
			Write-LogErr "Source : Line $line in script $script_name."
		}
		return $allVMData
	}

	[object] CreateNewPSSession([string] $server)
	{
		$newSession = $null
		$sessionPort = 5985
		$connectionURL = "http://${server}:${sessionPort}"
		$maxRetryTimes = 10
		$retryTime = 0
		$cred = Get-Cred -user $this.VHDUser -password $this.VHDPassword
		while ($retryTime -le $maxRetryTimes)
		{
			if (-not $this.LocalTest)
			{
				$newSession = New-PSSession -ConnectionUri $connectionURL -Credential $cred -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)
			}
			else {
				$newSession = New-PSSession -EnableNetworkAccess -ConnectionUri $connectionURL
			}
			if (($newSession) -and ($newSession.State -eq "Opened"))
			{
					Write-LogInfo "Session has been successfully opened"
					break
			}
			Start-Sleep -s 10
			$retryTime += 1
		}
		return $newSession
	}

	[string] GetIPAddress($session)
	{
		$cmd = "wsl ifconfig"
		$ifconfigOutput = Invoke-Command -Session $session -ScriptBlock {
			$output = Invoke-Expression $using:cmd
			return $output
		}
		Write-LogInfo "Output of IP address request is $ifConfigOutput"
		$ipAddress = Get-IPAddressFromIfconfig($ifConfigOutput)
		return $ipAddress
	}

	[object] CreateObjectNode([string] $ResourceGroup, [string] $TestLocation, [string] $RoleName, [string] $PublicIP, [string] $InternalIP, [string] $DistroName, [string] $Status)
	{
		$objNode = New-Object -TypeName PSObject
		Add-Member -InputObject $objNode -MemberType NoteProperty -Name ResourceGroupName -Value $ResourceGroup -Force
		Add-Member -InputObject $objNode -MemberType NoteProperty -Name Location -Value $TestLocation -Force
		Add-Member -InputObject $objNode -MemberType NoteProperty -Name RoleName -Value $RoleName -Force
		Add-Member -InputObject $objNode -MemberType NoteProperty -Name PublicIP -Value $PublicIP -Force
		Add-Member -InputObject $objNode -MemberType NoteProperty -Name InternalIP -Value $InternalIP -Force
		Add-Member -InputObject $objNode -MemberType NoteProperty -Name DistroName -Value $DistroName -Force
		return $objNode
	}

	[object] GetAllDeploymentData($ResourceGroup)
	{
		$allDeployedVMs = @()	
		Write-LogInfo "Collecting $ResourceGroup data.."
		Write-LogInfo "	Microsoft.Network/publicIPAddresses data collection in progress.."
		$RGIPsdata = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Network/publicIPAddresses" -Verbose -ExpandProperties
		Write-LogInfo "	Microsoft.Compute/virtualMachines data collection in progress.."
		$RGVMs = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Compute/virtualMachines" -Verbose -ExpandProperties
		Write-LogInfo "	Microsoft.Network/networkInterfaces data collection in progress.."
		$NICdata = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Network/networkInterfaces" -Verbose -ExpandProperties
		$currentRGLocation = (Get-AzResourceGroup -ResourceGroupName $ResourceGroup).Location
		Write-LogInfo "	Microsoft.Network/loadBalancers data collection in progress.."
		$LBdata = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Network/loadBalancers" -ExpandProperties -Verbose
		$RGIPData = $null
		foreach($ipData in $RGIPsdata) {
			if ((Get-AzPublicIpAddress -Name $ipData.name -ResourceGroupName $ipData.ResourceGroupName).IpAddress -ne "Not Assigned") {
				$RGIPdata = $ipData
			}
		}
		foreach ($testVM in $RGVMs)
		{
			$QuickVMNode = $this.CreateObjectNode($currentRGLocation, $this.TestLocation, "WSL2", $RGIPData, $RGIPData, "", $this.DistroName)
			$InboundNatRules = $LBdata.Properties.InboundNatRules
			foreach ($endPoint in $InboundNatRules)
			{
				if ( $endPoint.Name -imatch $testVM.ResourceName)
				{
					$endPointName = "$($endPoint.Name)".Replace("$($testVM.ResourceName)-","")
					Add-Member -InputObject $QuickVMNode -MemberType NoteProperty -Name "$($endPointName)Port" -Value $endPoint.Properties.FrontendPort -Force
				}
			}	
			foreach ( $nic in $NICdata )
			{
				if (($nic.Name.Replace("PrimaryNIC-","") -eq $testVM.ResourceName) -and ( $nic.Name -imatch "PrimaryNIC"))
				{
					$QuickVMNode.InternalIP = "$($nic.Properties.IpConfigurations[0].Properties.PrivateIPAddress)"
				}
				if (($nic.Name.Replace("ExtraNetworkCard-1-","") -eq $testVM.ResourceName) -and ($nic.Name -imatch "ExtraNetworkCard-1"))
				{
					$QuickVMNode.SecondInternalIP = "$($nic.Properties.IpConfigurations[0].Properties.PrivateIPAddress)"
				}
			}
			$QuickVMNode.ResourceGroupName = $ResourceGroup	
			$QuickVMNode.PublicIP = ($RGIPData | Where-Object { $_.Properties.publicIPAddressVersion -eq "IPv4" }).Properties.ipAddress
			$QuickVMNode.RoleName = $testVM.ResourceName
			$QuickVMNode.Status = $testVM.Properties.ProvisioningState
			$QuickVMNode.InstanceSize = $testVM.Properties.hardwareProfile.vmSize
			$QuickVMNode.Location = $currentRGLocation
			$allDeployedVMs += $QuickVMNode
		}
		Write-LogInfo "Collected $ResourceGroup data!"
		return $allDeployedVMs
	}

#region WSL2
	[bool] VerifyWSLSetup($session)
	{
		Write-LogInfo "Verifying WSL setup"
		# Test the version of build on the system
		$version = Invoke-Command -Session $session -ScriptBlock { `
				$version = [System.Environment]::OSVersion.Version.Build
				return $version
			}
		Write-LogInfo "Build version is $version."
		if ($version -ge "18917")
		{
			Write-LogInfo "Windows build version is greater than or equal to 18917, newer version of WSL 2 interface is available."
		}
		elseif ($version -lt "18873")
		{
			Write-LogErr "Windows build version must be 18873 or later.  Upgrade the Windows OS to run WSL tests."
			return $false
		}
		[hashtable]$features = @{
			"Microsoft-Windows-Subsystem-Linux" = $false
			"VirtualMachinePlatform" = $false
		}
		foreach ($feature in @($features.Keys))
		{
			Write-LogInfo "Checking the enable status of feature $feature, enabling if need be.  Reboot may be required."
			$successState = Invoke-Command -Session $session -ScriptBlock ${function:EnableWindowsOptionalFeatureForced} `
				-ArgumentList $feature
			switch ($successState) {
				"Enabled" { Write-LogInfo "Required $feature is enabled."; $features[$feature] = $true }
				"Reboot" { Write-LogInfo "The system needs to be rebooted for required feature $feature to be enabled." }
				"Unsupported" { Write-LogInfo "Required $feature is unsupported" }
				default { Write-LogInfo "Unexpected return state $successState when checking the enable state of required feature $feature." }
			}
		}
		foreach ($i in $features.Values)
		{
			if ($i -eq $false)
			{
				return $false
			}
		}
		return $true
	}

	[string] InstallDistribution([string] $server, $session)
	{
		Write-LogInfo "Installing Linux distribution on WSL"
		$oldInstalledDistros = $this.GetInstalledWSLDistros($server, $session)
		$distro = ""
		Write-Host "old install host distributions"
		Write-LogInfo "Installing new distribution $($this.DistroFilePath) on server $server"
		$output = Invoke-Command -Session $session `
			-ArgumentList $this.DistroFilePath, $this.DestinationDistroFilePath, $global:user, $global:password, $this.SSHPort `
			-ScriptBlock `
		{
			param ($distroFilePath, $destinationDistroFilePath, $username, $password, $SSHPort)
			$tarball = $false
			try {
				$sourceDistroFilePath = ""
				if ($distroFilePath.StartsWith("http"))
				{
					if (Test-Path -Path $destinationDistroFilePath)
					{
						Remove-Item -Path $destinationDistroFilePath -Recurse -Force
					}
					$downloadDirectory = $env:TEMP
					$fileToExtract = "distro.zip"
					$downloadPath = Join-Path -Path $downloadDirectory -ChildPath $fileToExtract
					Write-Output "downloadpath is $downloadPath"
					$oldProgressPreference = $ProgressPreference
					$ProgressPreference = 'SilentlyContinue'
					Invoke-WebRequest -Uri $distroFilePath -OutFile $downloadPath -UseBasicParsing
					$ProgressPreference = $oldProgressPreference
					if ((Test-Path -Path $downloadPath) -eq $false)
					{
						 $sourceDistroFilePath = ""
					}
					else {
						$sourceDistroFilePath = $downloadPath
					}
				}
				if (!$tarball)
				{
					Expand-Archive -Path $sourceDistroFilePath -DestinationPath $destinationDistroFilePath
				}

				$file = Get-ChildItem -Path $destinationDistroFilePath -Filter *.exe | Select-Object -Last 1
				$launchDistroCommand = Join-Path $destinationDistroFilePath $file
				Write-Output "launchDistroCommand is $launchDistroCommand"
				if (!$launchDistroCommand.EndsWith("exe")) {
					throw "Fail to find the exe file of WSL distro"
				} else {
					Write-Output "The distro launch command: $launchDistroCommand"
				}

				Write-Output "Installing the WSL distro with root"
				& $launchDistroCommand install --root
				Write-Output "Adding user account root, and configuring the SSH service"
				$encyptedPassword = & $launchDistroCommand run openssl passwd -crypt $password
				& $launchDistroCommand run useradd -m -p $encyptedPassword -s /bin/bash $username
				if (!$?)
				{
					throw "launchDistroCommand useradd failed with $LASTEXITCODE"
				}
				Write-Output "result of run useradd $lastExitCode"
				& $launchDistroCommand run usermod -aG sudo $username
				if (!$?)
				{
					throw "launchDistroCommand usermode failed with $LASTEXITCODE"
				}
				Write-Output "result of run usermod $lastExitCode"

#region New sshd_config replacement method
				# Modify the sshd_config file to allow password authentication and port 22 for SSH
				$config = & $launchDistroCommand run cat /etc/ssh/sshd_config
				if (!$?)
				{
					throw "launchDistroCommand cat ssjd_config failed with $LASTEXITCODE"
				}
				$config = (($config -replace ".*PasswordAuthentication .*", "PasswordAuthentication yes") -replace ".*Port .*", "Port $SSHPort")
				$config | Out-File -Force sshd_config
				#Convert from Windows line endings to Unix line ending
				(Get-Content sshd_config -Raw).Replace("`r`n","`n") | Set-Content sshd_config -Force
				$newConfig = Get-Content sshd_config
				Remove-Item -Force sshd_config
				# Create a bash here document to send to the distribution
				$command = "cat > /etc/ssh/sshd_config << END`n"
				foreach ($line in $newConfig)
				{
					$command = "{0}`n{1}" -f $command,$line
				}
				$command = "{0}`nEND" -f $command

				# Send the here document to the distribution
				& $launchDistroCommand run $command
				if (-not $?)
				{
					throw "launchDistroCommand update sshd_config failed with $LASTEXITCODE"
				}
				netsh advfirewall firewall add rule name="Open Port $SSHPort for LISAv2 run $global:TestID" dir=in action=allow protocol=TCP localport=$SSHPort
				if (-not $?)
				{
					throw "netsh advfirewall add rule to open port $SSHPort failed with $LASTEXITCODE"
				}

				& $launchDistroCommand run ssh-keygen -A
				if (-not $?)
				{
					throw "launchDistroCommand ssh-keygen failed with $LASTEXITCODE"
				}

				& $launchDistroCommand run service ssh restart
				if (-not $?)
				{
					throw "run service ssh restart failed with $LASTEXITCODE"
				}
			}
			catch {
				$e = $_.Exception
				$line = $_.InvocationInfo.ScriptLineNumber
				$msg = $e.Message
				Write-Output -ForegroundColor Red "caught exception: $e at line $line, message $msg"
			}
		}
		Write-LogInfo $output
		if ($output -match "exception")
		{
			throw "Halt LISAv2 execution, $output"
		}

		$newInstalledDistros = $this.GetInstalledWSLDistros($server, $session)
		foreach ($foundDistro in $newInstalledDistros) {
			if ($oldInstalledDistros -notcontains $foundDistro) {
				Write-LogInfo "found new distro $foundDistro, enabling WSL v2 on it."
				$success = $this.EnableWSLV2OnDistribution($server, $session, $foundDistro)
				if (!$success)
				{
					Write-LogInfo "Failed to enable WSL 2."
					$distro = ""
				}
				else
				{
					$distro = $foundDistro 
					
					$ipAddress = $this.GetIPAddress($session)
					Write-LogInfo "WSL2 Vm IP is $ipAddress and distro is $distro"
					if (-not ($this.IsWSLRunning($distro, $ipAddress)))
					{
						throw "WSL is not running, IP address cannot be pinged, or pscp.exe does not work."
					}
				}
				break
			}
		}
		return $distro
	}
	
	[bool] IsExtensionTarball([string] $ext)
	{
		if (($ext -eq ".tar.gz") -or ($ext -eq ".tgz"))
		{
			return $true
		}
		return $false
	}

	[string] ConvertUnicodeToAscii([string] $inputString)
	{
		$outputString = $inputString.Replace("`0", "")
		return $outputString
	}

	#TODO this should be part of an invoke-command
	[bool] EnableWSLV2OnDistribution([string] $server, $session, [string] $distro)
	{
		$success = $false
		Write-LogInfo "Enabling vmmode on distro $distro using the newer method."
		$output = Invoke-Command -Session $session -ArgumentList $distro `
		-ScriptBlock  {
			param ($distro)
			wsl --set-version $distro 2
			wsl --set-default $distro
			wsl --set-default-version 2
		}
		Write-Output $output
		if ($output -match "exception")
		{
			throw "Halt LISAv2 execution, $output"
		}
		$allDistros = Invoke-Command -Session $session `
		-ScriptBlock  {
			wsl --list --verbose
		}
		Write-LogInfo "Enabled vmmode on distro $distro using the newer method."
		#$allDistros = wsl --list --verbose
		Write-LogInfo " print all distro : $allDistros"
		foreach ($line in $allDistros)
		{
			$line = $this.ConvertUnicodeToAscii($line)
			if ($line -eq "")
			{
				Write-LogInfo "inside $line"
				continue
			}
			Write-Host $line
			if ($line -match "^`*$distro\s+[a-zA-Z].*2")
			{
				Write-Host "running WSL2 on distro $distro, line $line"
				$success = $true
				break
			}
		}
		if (!$success)
		{
			Write-Host "not running WSL2"
		}
		Write-Host "Return result $success"
		return $success
	}
#endregion WSL2

[void] DeleteTestVMs($allVMData, $SetupTypeData, $UseExistingRG) {
	$rgs = @()
	foreach ($vmData in $AllVMData) {
		$rgs += $vmData.ResourceGroupName
	}
	$uniqueRgs = $rgs | Select-Object -Unique
	foreach ($rg in $uniqueRgs) {
		$isCleaned = Delete-ResourceGroup -RGName $rg -UseExistingRG $UseExistingRG
		if (!$isCleaned)
		{
			Write-LogInfo "Failed to trigger delete resource group $rg.. Please delete it manually."
		}
		else
		{
			Write-LogInfo "Successfully cleaned up RG ${rg}.."
		}
	}
}

	[object] GetInstalledWSLDistros($Server, $session) {
		Write-LogInfo "Getting the installed WSL distros on server $Server"
		$installedDistros = @()
		$distros = Invoke-Command -Session $session -ScriptBlock {
			$outputList = & wslconfig /l
			$distroList = @()
			for ($index=1; $index -lt $outputList.Length; $index++) {
				$distro = $outputList[$index].Replace("`0", "").Replace("(Default)", "")
				if ($distro -ne "") {
					$distroList += $distro.Trim()
				}
			}
			return $distroList
		}
		$installedDistros += $distros
		Write-LogInfo "$installedDistros"
		return $installedDistros
	}
}