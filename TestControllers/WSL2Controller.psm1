##############################################################################################
# WSL2Controller.psm1
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
# Operations :
#
<#
.SYNOPSIS
	PS modules for LISAv2 test automation
	This module drives the test on version 2 of the Windows Subsystem of Linux

.PARAMETER
	<Parameters>

.INPUTS


.NOTES
	Creation Date:
	Purpose/Change:

.EXAMPLE

#>
###############################################################################################
using Module ".\TestController.psm1"
using Module "..\TestProviders\WSL2Provider.psm1"
using Module "..\Libraries\Azure.psm1"

Class WSL2Controller : TestController
{
	[string] $OsVHD
	[string] $TestLocation
	[bool] $LocalTest = $false
	[bool] $LocalVHD = $false
	[string] $VHDUserName
	[string] $VHDUserPassword
	[string] $DestinationOsVhdPath
	[string] $DistroFilePath
	[string] $DestinationDistroFilePath
	[string] $StorageAccount
	[string] $DestinationResourceGroup
	[string] $CustomKernel
	[bool] $newWsl2 = $false

	WSL2Controller() {
		$this.TestPlatform = "WSL2"
		$this.TestProvider = New-Object -TypeName "WSL2Provider"
	}

	[void] ParseAndValidateParameters([Hashtable]$ParamTable) {
		try {
			
			$this.StorageAccount = $ParamTable["StorageAccount"]

			# if ($this.CustomParams["OSType"] -ne "Windows")
			# {
			# 	$parameterErrors += "-CustomParam OSType of Windows is required."
			# }

			$parameterErrors = ([TestController]$this).ParseAndValidateParameters($ParamTable)

			$this.RGIdentifier = $ParamTable["RGIdentifier"]

			# Custom kernel which will be placed in the host user's directory.
			# TODO currently not implemented but could be used for automation.
			$this.CustomKernel = $ParamTable["CustomKernel"]

			if (!$this.OsVHD) {
				$parameterErrors += "-OsVHD <'VHD_Name.vhd'> or -OsVHD None is required."
			}

			if ($this.OsVHD -eq "None")
			{
				if ($this.TestLocation -eq "")
				{
					throw "Test location needs to be a host name for OsVHD of None"
				}

				if ($this.TestLocation -eq "localhost")
				{
					$this.LocalTest = $true
				}
				else {
					$this.LocalTest = $false
				}
	
				#TODO Add later as the test location could be a host name outside of Azure so
				#it should be verified.
				# try {
				# 	Test-Connection -ComputerName $this.TestLocation					
				# }
				# catch {
				# 	throw "Host name for test location does not exist"
				# }
			}

			if (-not $this.LocalTest)
			{
				if ([System.IO.Path]::GetExtension($this.OsVHD) -ne ".vhd" -and !$this.OsVHD.Contains("vhd")) {
					$parameterErrors += "-OsVHD $($this.OsVHD) does not have .vhd extension required by Platform Azure."
				}
				if (!$this.TestLocation) {
					$parameterErrors += "-TestLocation <AzureRegion> is required."
				}
			}

			if ($parameterErrors.Count -gt 0) {
				$parameterErrors | ForEach-Object { Write-LogErr $_ }
				throw "Failed to validate the test parameters provided. Please fix above issues and retry."
			} else {
				Write-LogInfo "Test parameters for WSLVM have been validated successfully. Continue running the test."
			}
		}
		catch {
			$e = $_.Exception
			$line = $_.InvocationInfo.ScriptLineNumber
			$msg = $e.Message
			Write-Host -ForegroundColor Red "caught exception: $e at line $line, message $msg"
			throw
		}
	}
		
	[void] PrepareTestEnvironment($XMLSecretFile) {
		([TestController]$this).PrepareTestEnvironment($XMLSecretFile)

		$vmwslConfig = $this.GlobalConfig.Global.WSL2
		$azureConfig = $this.GlobalConfig.Global.Azure
		$secrets = $this.XMLSecrets.secrets
		if ($secrets) {
			$azureConfig.Subscription.SubscriptionID = $secrets.SubscriptionID
			$azureConfig.TestCredentials.LinuxUsername = $secrets.linuxTestUsername
			$azureConfig.TestCredentials.LinuxPassword = $secrets.linuxTestPassword
			$vmwslConfig.ResultsDatabase.server = $secrets.DatabaseServer
			$vmwslConfig.ResultsDatabase.user = $secrets.DatabaseUser
			$vmwslConfig.ResultsDatabase.password = $secrets.DatabasePassword
			$vmwslConfig.ResultsDatabase.dbname = $secrets.DatabaseName
			$vmwslConfig.DistroFilePath = $secrets.VMWSLDistributionPath
			$vmwslConfig.DestinationDistroFilePath = $secrets.VMWSLDestinationDistributionPath
			$vmwslConfig.VHDUserName = $secrets.VMWSLVHDUserName
			$vmwslConfig.VHDPassword = $secrets.VMWSLVHDPassword
			$vmwslConfig.SSHPort = $secrets.VMWSLSSHPort
			Add-AzureAccountFromSecretsFile -CustomSecretsFilePath $XMLSecretFile
		}
		$this.VmUserName = $azureConfig.TestCredentials.LinuxUsername
		$this.VmPassword = $azureConfig.TestCredentials.LinuxPassword
		
		# TODO replace localtest with a specific host name such as localhost for a local test
		if (-not $this.LocalTest)
		{
			$RegionAndStorageMapFile = Resolve-Path ".\XML\RegionAndStorageAccounts.xml"
			if (Test-Path $RegionAndStorageMapFile) {
				$RegionAndStorageMap = [xml](Get-Content $RegionAndStorageMapFile)
			} else {
				throw "File $RegionAndStorageMapFile does not exist"
			}
			# global variables: StorageAccount, TestLocation
			if ( $this.StorageAccount -imatch "ExistingStorage_Standard" )
			{
				$azureConfig.Subscription.ARMStorageAccount = $RegionAndStorageMap.AllRegions.$($this.TestLocation).StandardStorage
				Write-LogInfo "Selecting existing standard storage account in $($this.TestLocation) - $($azureConfig.Subscription.ARMStorageAccount)"
			}
			elseif ( $this.StorageAccount -imatch "ExistingStorage_Premium" )
			{
				$azureConfig.Subscription.ARMStorageAccount = $RegionAndStorageMap.AllRegions.$($this.TestLocation).PremiumStorage
				Write-LogInfo "Selecting existing premium storage account in $($this.TestLocation) - $($azureConfig.Subscription.ARMStorageAccount)"
			}
			elseif ( $this.StorageAccount -imatch "NewStorage_Standard" )
			{
				$azureConfig.Subscription.ARMStorageAccount = "NewStorage_Standard_LRS"
			}
			elseif ( $this.StorageAccount -imatch "NewStorage_Premium" )
			{
				$azureConfig.Subscription.ARMStorageAccount = "NewStorage_Premium_LRS"
			}
			elseif ($this.StorageAccount)
			{
				$sc =  Get-AzStorageAccount | Where-Object {$_.StorageAccountName -eq $this.StorageAccount}
				if (!$sc) {
					Throw "Provided storage account $($this.StorageAccount) does not exist, abort testing."
				}
				if($sc.Location -ne $this.TestLocation) {
					Throw "Provided storage account $($this.StorageAccount) location $($sc.Location) is different from test location $($this.TestLocation), abort testing."
				}
				$azureConfig.Subscription.ARMStorageAccount = $this.StorageAccount.Trim()
				Write-LogInfo "Selecting custom storage account : $($azureConfig.Subscription.ARMStorageAccount) as per your test region."
			}
			else
			{
				$azureConfig.Subscription.ARMStorageAccount = $RegionAndStorageMap.AllRegions.$($this.TestLocation).StandardStorage
				Write-LogInfo "Auto selecting storage account : $($azureConfig.Subscription.ARMStorageAccount) as per your test region."
			}
		}

		if( $this.ResultDBTable )
		{
			$vmwslConfig.ResultsDatabase.dbtable = ($this.ResultDBTable).Trim()
			Write-LogInfo "ResultDBTable : $($this.ResultDBTable) added to GlobalConfig.Global.HyperV.ResultsDatabase.dbtable"
		}
		if( $this.ResultDBTestTag )
		{
			$vmwslConfig.ResultsDatabase.testTag = ($this.ResultDBTestTag).Trim()
			Write-LogInfo "ResultDBTestTag: $($this.ResultDBTestTag) added to GlobalConfig.Global.HyperV.ResultsDatabase.testTag"
		}

		Write-LogInfo "------------------------------------------------------------------"

		if (-not $this.LocalTest)
		{
			$SelectedSubscription = Select-AzSubscription -SubscriptionId $azureConfig.Subscription.SubscriptionID
			$subIDSplitted = ($SelectedSubscription.Subscription.SubscriptionId).Split("-")
			$userIDSplitted = ($SelectedSubscription.Account.Id).Split("-")
			Write-LogInfo "SubscriptionName       : $($SelectedSubscription.Subscription.Name)"
			Write-LogInfo "SubscriptionId         : $($subIDSplitted[0])-xxxx-xxxx-xxxx-$($subIDSplitted[4])"
			Write-LogInfo "User                   : $($userIDSplitted[0])-xxxx-xxxx-xxxx-$($userIDSplitted[4])"
			Write-LogInfo "ServiceEndpoint        : $($SelectedSubscription.Environment.ActiveDirectoryServiceEndpointResourceId)"
			Write-LogInfo "CurrentStorageAccount  : $($azureConfig.Subscription.ARMStorageAccount)"
		}
		
		Write-LogInfo "------------------------------------------------------------------"

		Write-LogInfo "Setting global variables"
		$this.SetGlobalVariables()
		Write-LogInfo "LocalTest is $($this.LocalTest)"
		$this.TestProvider.Initialize($vmwslConfig)
	}

	[void] PrepareTestImage() {

		if (-not $this.LocalTest)
		{
			#If Base OS VHD is present in another storage account, then copy to test storage account first.
			if ($this.OsVHD.StartsWith("http"))
			{
				$useSASURL = $false
				if (($this.OsVHD -imatch 'sp=') -and ($this.OsVHD -imatch 'sig=')) {
					$useSASURL = $true
				}

				$ARMStorageAccount = $this.GlobalConfig.Global.Azure.Subscription.ARMStorageAccount
				if ($ARMStorageAccount -imatch "NewStorage_") {
					Throw "LISAv2 only supports copying VHDs to existing storage account."
				}

				if (!$useSASURL -and ($this.OsVHD -inotmatch "/")) {
					$this.OsVHD = 'http://{0}.blob.core.windows.net/vhds/{1}' -f $ARMStorageAccount, $this.OsVHD
				}

				#Check if the test storage account is same as VHD's original storage account.
				$givenVHDStorageAccount = $this.OsVHD.Replace("https://","").Replace("http://","").Split(".")[0]
				$sourceContainer =  $this.OsVHD.Split("/")[$this.OsVHD.Split("/").Count - 2]
				$vhdName = $this.OsVHD.Split("?")[0].split('/')[-1]

				if ($givenVHDStorageAccount -ne $ARMStorageAccount) {
					Write-LogInfo "Your test VHD is not in target storage account ($ARMStorageAccount)."
					Write-LogInfo "Your VHD will be copied to $ARMStorageAccount now."

					#Copy the VHD to current storage account.
					#Check if the OsVHD is a SasUrl
					if ($useSASURL) {
						$copyStatus = Copy-VHDToAnotherStorageAccount -SasUrl $this.OsVHD -destinationStorageAccount $ARMStorageAccount -destinationStorageContainer "vhds" -vhdName $vhdName
						$this.OsVHD = 'http://{0}.blob.core.windows.net/vhds/{1}' -f $ARMStorageAccount, $vhdName
					} else {
						$copyStatus = Copy-VHDToAnotherStorageAccount -sourceStorageAccount $givenVHDStorageAccount -sourceStorageContainer $sourceContainer -destinationStorageAccount $ARMStorageAccount -destinationStorageContainer "vhds" -vhdName $vhdName
					}
					if (!$copyStatus) {
						Throw "Failed to copy the VHD to $ARMStorageAccount"
					}
				} else {
					$sc = Get-AzStorageAccount | Where-Object {$_.StorageAccountName -eq $ARMStorageAccount}
					$storageKey = (Get-AzStorageAccountKey -ResourceGroupName $sc.ResourceGroupName -Name $ARMStorageAccount)[0].Value
					$context = New-AzStorageContext -StorageAccountName $ARMStorageAccount -StorageAccountKey $storageKey
					$blob = Get-AzStorageBlob -Blob $vhdName -Container $sourceContainer -Context $context -ErrorAction Ignore
					if (!$blob) {
						Throw "Provided VHD not existed, abort testing."
					}
				}
				Set-Variable -Name BaseOsVHD -Value $this.OsVHD -Scope Global
				Write-LogInfo "New Base VHD name - $($this.OsVHD)"
			}
			else
			{
				if (-not (Test-Path $this.OsVHD))
				{
					throw "Local path $this.OsVHD of OS VHD does not exit"
				}
				else
				{
					$leaf = Split-Path -Path $this.OsVHD -Leaf

					# Add the VHD to Azure
					$urlOfUploadedImageVhd = "https://$($this.StorageAccount).blob.core.windows.net/vhds/$leaf"

					$this.DestinationResourceGroup = "$this.RGIdentifier"

					# $assumeVhdPresent = $false
					# if (-not $assumeVhdPresent)
					# {
						Add-AzVhd -ResourceGroupName ([TestController]$this).RGIdentifier `
							-Destination $urlOfUploadedImageVhd `
							-NumberOfUploaderThreads 32 `
							-LocalFilePath $this.OsVHD `
							-OverWrite `
							-ErrorAction SilentlyContinue
					# }

					Set-Variable -Name BaseOsVHD -Value $this.OsVHD -Scope Global	
					Write-LogInfo "Local Base VHD name - $($this.OsVHD)"
				}
			}
		}
	}
}
