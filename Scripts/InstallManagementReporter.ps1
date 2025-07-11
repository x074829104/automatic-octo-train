<#
.Synopsis
   Installs Management Reporter
.DESCRIPTION
   Installs Management Reporter to $InstallLocation using the MSI specified either by MsiPath or local to this script.
#>
[CmdletBinding()]
Param
(
	# Log file set from Deployment task.
	[string]
	$log,

	# JSON encoded dictionary containing configuration settings from Deployment task.
	[string]
	$config,

	# Used by DSC, actual XML file in base64 form. Use if cert data/info is needed.
	[string]
	$serviceModelXml,

	# On fileshare script's location is used, on OneBox $env:dplLogDir is used.
	[string]
	$LogPath = "$PSScriptRoot",

	# Indicates to not install or remove MSI.
	[switch]
	$NoInstall,

	# Path to directory containing MSI and CAB file for MR server. Supports shortcut (.lnk) files. This path is used if the MSI is not next to this script file.
	[string]
	$MsiPath = '\\cpmint-file01\builds\mr\AX7_Build.lnk',

	# Indicates to force the -MsiPath to be used.
	[switch]
	$ForceMsiPath,

	# Indicates to force a non-recursive search for the MSI file.
	[switch]
	$ForceNonRecursiveFind,

	# Indicates to suppresses any warnings that would show from -Remove.
	[switch]
	$SuppressWarning,

	# Path to install MSI to, this overrides the default settings of the MSI. Default is c:\FinancialReporting.
	[string]
	$InstallLocation = 'c:\FinancialReporting',

	# Indicates this is an upgrade vs. a clean install
	[switch]
	$Upgrade
)

. "$PSScriptRoot\ScriptSetup.ps1"
Set-LogPath -FullLogPath $log -LogDir $LogPath
if ($log -and !$LogPath)
{
	$LogPath = [System.IO.Path]::GetDirectoryName($log)
}

Write-EnvironmentDataToLog
$Settings = Get-SettingsObject -Config $config -ServiceModelXml $serviceModelXml

function Install-Msi
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0)]
		[string]
		[ValidateNotNullOrEmpty()]
		$PackagePath,

		[Parameter(ParameterSetName = 'Install')]
		[switch]
		$Install,

		[Parameter(ParameterSetName = 'AdministratorInstall')]
		[switch]
		$AdminInstall,

		[Parameter(ParameterSetName = 'Uninstall')]
		[switch]
		$Uninstall,

		[Parameter(ParameterSetName = 'Repair')]
		[switch]
		$Repair,

		[switch]
		$Quiet,

		[switch]
		$Passive,

		[switch]
		$NoRestart,

		[switch]
		$PromptRestart,

		[switch]
		$ForceRestart,

		[switch]
		$Log,

		[string]
		$LogName,

		[string]
		[ValidateNotNullOrEmpty()]
		$LogDirectory = '.',

		[Hashtable]
		$Properties
	)

	if(!(Test-Path $PackagePath))
	{
		throw "$PackagePath was an invalid MSI package path"
	}

	[string[]]$commands = @()
	
	if($Install) 
	{
		$commands += '/i' 
	}
	elseif($AdminInstall) 
	{
		$commands += '/a' 
	}
	elseif($Uninstall) 
	{
		$commands += '/x' 
	}
	elseif($Repair)
	{
		$commands += '/fp' 
	}

	$PackagePath = $PackagePath.Trim('"').Trim() # remove start and ending double-quotes and any trailing whitespace
	$commands += "`"$PackagePath`""

	if($Quiet) 
	{
		$commands += '/quiet' 
	}
	if($Passive) 
	{
		$commands += '/passive' 
	}
	if($NoRestart) 
	{
		$commands += '/norestart' 
	}
	if($PromptRestart) 
	{
		$commands += '/promptrestart' 
	}
	if($ForceRestart) 
	{
		$commands += '/forcerestart' 
	}

	if($Log)
	{
		if(!$LogName)
		{
			$LogName = Join-Path -Path (Resolve-Path $LogDirectory).Path -ChildPath "$([System.IO.Path]::GetFileNameWithoutExtension($PackagePath))_$(Get-Date -Format yyyyMMdd-HHmmss).log"
		}
		else
		{
			$LogName = $LogName.Trim('"').Trim()
		}

		Write-LogMessage -Message "MSI log will be available at $LogName"

		$commands += '/log'
		$commands += "`"$LogName`""
	}

	if($Properties)
	{
		foreach($property in $Properties.GetEnumerator())
		{
			$commands += "$($property.Key.ToString().Trim().ToUpperInvariant())=`"$($property.Value.ToString().Trim())`""
		}
	}

	$execute = 'msiexec.exe ' + [string]::Join(' ', $commands)
	Write-Debug -Message $execute
	$p = Start-Process -FilePath msiexec.exe -Wait -ArgumentList $commands -PassThru
	if($p.ExitCode -ne 0)
	{
		$logFileMessage = 'specify -Log to Install-Msi for capturing log'
		if($Log)
		{
			$logFileMessage = "log available at $LogName"
		}

		throw "MSIEXEC exited with error code $($p.ExitCode), $logFileMessage"
	}

	Write-LogMessage -Message "[Success] Executing $execute"
}

function Find-MRInstaller
{
	[CmdletBinding()]
	Param
	(
		# Param1 help description
		[Parameter(ValueFromPipeline = $true, Position = 0)]
		[string]
		$MsiDirectoryPath,

		[Parameter(ParameterSetName = 'Server')]
		[switch]
		$Server,

		[Parameter(ParameterSetName = 'Client')]
		[switch]
		$Client,

		[switch]
		$RecursiveFind,

		[switch]
		$ForceMsiDirectoryPath
	)

	# If not using recursive find, no point adding PSScriptRoot because it is always a directory
	if(!$RecursiveFind -or $ForceMsiDirectoryPath)
	{
		 $possibleLocations = @($MsiDirectoryPath)
	}
	else
	{
		 $possibleLocations = @($PSScriptRoot, $MsiDirectoryPath)
	}
   
	[string] $msiName = ''
	if($Server)
	{
		$msiName = Get-MRInstallerName -Server
	}
	else
	{
		$msiName = Get-MRInstallerName -Client
	}

	foreach($location in $possibleLocations)
	{
		# because PSScriptRoot will always be valid, it's safe to say the issue is MsiDirectoryPath
		if([string]::IsNullOrEmpty($location))
		{
			throw "Empty or null path specified for -MsiDirectoryPath, $location"
		}

		if(!(Test-Path $location))
		{
			throw "Invalid path supplied for -MsiDirectoryPath, $location"
		}

		if($location.EndsWith('.lnk'))
		{
			$shell = New-Object -ComObject WScript.Shell
			$location = Get-ChildItem -Path $location -Filter *.lnk |
				ForEach-Object -Process {
					$shell.CreateShortcut($_.FullName).TargetPath 
				} |
				Select-Object -First 1
			
			if(!(Test-Path $location))
			{
				throw "Invalid path specified in shortcut for -MsiDirectoryPath, $MsiDirectoryPath"
			}
		}

		if($RecursiveFind)
		{
			$msiFilePath = Get-ChildItem -Path $location -Filter $msiName -Recurse |
				Sort-Object -Descending -Property CreationTime |
				Select-Object -First 1 |
				ForEach-Object -Process {
					$_.FullName 
				}

			if($msiFilePath)
			{
				return $msiFilePath
			}
			else
			{
				continue
			}
		}
		else
		{
			$msiFilePath = Join-Path -Path $location -ChildPath $msiName
			if(!(Test-Path $msiFilePath))
			{
				throw "Unable to find $msiFilePath"
			}

			return $msiFilePath
		}
	}
	
	throw "Unable to find MSI named $msiName"
}

function Copy-MRInstaller
{
	[CmdletBinding()]
	Param
	(		
		[ValidateNotNullOrEmpty()]
		[string]
		$MsiFilePath,
		
		[ValidateNotNullOrEmpty()]
		[string]
		$InstallLocation
	)

	$file = Get-ChildItem -Path $MsiFilePath
	$folder = $file.Directory.FullName
	$msiLocation = Join-Path -Path $folder -ChildPath 'MRServer_x64.msi'
	$msiDestination = Join-Path -Path $InstallLocation -ChildPath 'MRServer_x64.msi'

	if($msiLocation -eq $msiDestination)
	{
		Write-LogMessage -Message "Installation media is already in place." -Verbose
	}
	else
	{
		Copy-Item -Path $msiLocation -Destination $InstallLocation -Force
		Copy-Item -Path (Join-Path -Path $folder -ChildPath 'MRServer.cab') -Destination $InstallLocation -Force
	}
	Write-LogMessage -Message "[Success] Copying installation media"
}

function Install-MRServer
{
	[CmdletBinding()]
	Param
	(
		[string]
		$SearchPath,

		[switch]
		$NoRecursive,

		[switch]
		$ForceSearchPath,

		[string]
		$LogDirectory = "$PSScriptRoot",

		[switch]
		$NoLog,

		[string]
		$InstallLocation,
		
		[switch]
		$Upgrade
	)

	# See if MR was previously installed
	$mrPaths = Get-MRFilePaths -SuppressError:(!$Upgrade)
	if(!$Upgrade -and $mrPaths)
	{
		Write-LogMessage -Message "A previous install of MR was detected. Exiting the script execution." -Warning
		return
	}

	# For upgrade, use the existing install location
	if($Upgrade)
	{
		$InstallLocation = $mrPaths.InstallLocation
	}

	$msiFilePath = Find-MRInstaller -MsiDirectoryPath $SearchPath -Server -RecursiveFind:(!$NoRecursive) -ForceMsiDirectoryPath:$ForceSearchPath

	Write-LogMessage -Message "Installing MR server from '$msiFilePath'"

	[hashtable]$properties = $null
	if($InstallLocation)
	{
		$properties = @{'INSTALLLOCATION' = $InstallLocation; 'TARGETPLATFORM' = 'Cloud'}
	}

	Install-Msi $msiFilePath -Install -Quiet -Log -LogDirectory $LogDirectory -Properties:$properties
	Install-Msi $msiFilePath -Repair -Quiet -Log -LogDirectory $LogDirectory -Properties:$properties
	Copy-MRInstaller -MsiFilePath $msiFilePath -InstallLocation $InstallLocation
}

function Restart-EventTraceCollection
{
	[CmdletBinding()]
	Param
	(
	)

	if($LogPath)
	{
		$mrEtwProviderPath = 'Microsoft-Dynamics-MR*'
		Write-LogMessage -Message "Restarting event tracing collection by exporting and clearing any MR event traces with provider name '$mrEtwProviderPath'"
		$eventLogDirectory = Join-Path -Path $LogPath -ChildPath 'PreviousInstallEventLogs'
		Write-LogMessage -Message "Using this directory for exporting previous event traces: $eventLogDirectory"
		# Each execution of this script should have a unique directory but for executing MRServiceModelDeployment.ps1 this won't be the case
		if(Test-Path -Path $eventLogDirectory)
		{
			Remove-Item $eventLogDirectory -Recurse -Force
		}

		[void](New-Item -Path $eventLogDirectory -ItemType Directory -Force)
		$mrLogs = wevtutil el | Where-Object { $_ -like $mrEtwProviderPath }
		if ($mrLogs)
		{
			$nonEmptyMRLogs = $mrLogs | Where-Object {
				$eventLog = wevtutil gli "$_"
				$eventLog -ne $null -and $eventLog -inotcontains 'numberOfLogRecords: 0'
			}

			if ($nonEmptyMRLogs)
			{
				$nonEmptyMRLogs | ForEach-Object { 
					Write-LogMessage -Message "Exporting $_"
					wevtutil epl "$_" "$eventLogDirectory\$($_.Replace('/', '_')).evtx" 
				}

				$nonEmptyMRLogs | ForEach-Object { 
					Write-LogMessage -Message "Clearing $_"
					wevtutil sl "$_" /e:false /q # Disable the log
					wevtutil cl "$_"          # Clear the log
					wevtutil sl "$_" /e:true /q # Re-enable the log
				}

				Write-LogMessage -Message '[Success] Exported and cleared MR event traces'
			}
			else
			{
				Write-LogMessage -Message 'All MR event traces were empty'
			}
		}
		else
		{
			Write-LogMessage -Message "No existing MR event traces were found"
		}		
	}
	else
	{
		Write-LogMessage -Message 'No LogPath specified, unable to restart event trace collection' -Warning
	}
}

$installManagementReporterScript = New-ScriptExecution -Name 'Installing Management Reporter' `
	-ErrorCode $ErrorCodes.InstallManagementReporter `
	-Script {
		if(!$NoInstall)
		{
			if((Test-Path variable:Settings) -and $Settings)
			{				
				# Some of these settings get applied here, some get applied to MRDefaultValues
				Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.InstallPath' -UpdateObject:([ref]$InstallLocation) -UpdateObjectName 'InstallLocation'
			}

			Install-MRServer -SearchPath $MsiPath -NoRecursive:$ForceNonRecursiveFind -ForceSearchPath:$ForceMsiPath -LogDirectory $LogPath -InstallLocation:$InstallLocation -Upgrade:$Upgrade
			Restart-EventTraceCollection -ErrorAction Continue # Don't let this fail deployment but show errors if something doesn't work

			# Write values that include the key vault settings so other deployment components can access them
			Import-MRDeployModule
			if(!(Test-Path variable:MRDefaultValues))
			{
				$MRDefaultValues = @{}
			}
			if((Test-Path variable:Settings) -and $Settings)
			{	
				Update-ValueFromConfig -Settings $Settings -PropertyName 'Infrastructure.AzureKeyVaultAppId' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'KeyVaultClientId'
				Update-ValueFromConfig -Settings $Settings -PropertyName 'Infrastructure.AzureKeyVaultName' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'KeyVaultUrl'
				Update-ValueFromConfig -Settings $Settings -PropertyName 'Infrastructure.AzureKeyVaultCertThumbprint' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'KeyVaultCertThumbprint'
			
				. "$PSScriptRoot\UpdateDefaultValues.ps1"

				$writeServiceSettingsParams = Get-WriteServiceSettingsParams -ServiceType Services
				Write-ServiceSettings @writeServiceSettingsParams
				Write-MRStepMessage 'Writing service settings to deployment config file (Write-DeploymentConfigSettings)'
				$deploymentWriteConfigSettingsParams = Get-WriteDeploymentConfigSettingsParams
				Write-DeploymentConfigSettings @deploymentWriteConfigSettingsParams
				[System.Configuration.ConfigurationManager]::RefreshSection("appSettings")
				Write-MRInfoMessage 'Wrote deployment application configuration settings' -Success
			}

		}
		else
		{
			$result = Test-MRInstalled
			if(!$result)
			{
				throw 'MR is not installed and -NoInstall was specified'
			}
		}
	}

Invoke-ExecutionScript -ExecutionScript $installManagementReporterScript
# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC6zsqp14+qOuD7
# QYdI+cGcMSpQdk8HR/VISnk3cckSZ6CCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWzCCFVcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgfx68uN9o
# Kyc06Oj6Bsor0D5RGm/b3fZD3WHbv936FhIwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBpv5tG9Frhx9dvNumnc67cASD202AJIB+oxOub11pB
# JjddVfNmil2SmufNTH51MVLlAe6AfZi8MynqtlS3Z2PTLuXm9AvZD+BPK9mn9KHF
# 9/qMP7v4rTtfzSEUiFp8960NUKdK7LJZ52bulANOFQoebEYvkSauMm06zH/mFmK8
# /hbIVWvahRzKUAcF/uucEauGskvHm2sPFCN0++bM4s/lVnZKUzWgNpr7kQtvzPO7
# cYUVr4gqe6nrpJ6yuXLQSUP6UMp1mAZmFNmbRBYLZFhUW2jwbB4HQyk160HRo6IZ
# 9DpPr1TJZRyGBbWoUOCVj7jRwC9zRY69ianwzN01+QIWoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIK2/HQAmHUpwkt2FsXQRxch4usZFWSfljABgXVaq
# Aol4AgZhktY1Bs4YEzIwMjExMjAxMDgzODA5LjYwNVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjhBODItRTM0Ri05RERBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAFLT7KmSNXkwlEAAAAAAUsw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNTU5WhcNMjIwMjExMTgyNTU5WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEE4Mi1FMzRGLTlE
# REExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChNnpQx3YuJr/ivobPoLtpQ9egUFl8
# THdWZ6SAKIJdtP3L24D3/d63ommmjZjCyrQm+j/1tHDAwjQGuOwYvn79ecPCQfAB
# 91JnEp/wP4BMF2SXyMf8k9R84RthIdfGHPXTWqzpCCfNWolVEcUVm8Ad/r1LrikR
# O+4KKo6slDQJKsgKApfBU/9J7Rudvhw1rEQw0Nk1BRGWjrIp7/uWoUIfR4rcl6U1
# utOiYIonC87PPpAJQXGRsDdKnVFF4NpWvMiyeuksn5t/Otwz82sGlne/HNQpmMzi
# gR8cZ8eXEDJJNIZxov9WAHHj28gUE29D8ivAT706ihxvTv50ZY8W51uxAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUUqpqftASlue6K3LePlTTn01K68YwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAFtq51Zc/O1AfJK4tEB2Nr8bGEVD5qQ8l8gXIQMrM
# ZYtddHH+cGiqgF/4GmvmPfl5FAYh+gf/8Yd3q4/iD2+K4LtJbs/3v6mpyBl1mQ4v
# usK65dAypWmiT1W3FiXjsmCIkjSDDsKLFBYH5yGFnNFOEMgL+O7u4osH42f80nc2
# WdnZV6+OvW035XPV6ZttUBfFWHdIbUkdOG1O2n4yJm10OfacItZ08fzgMMqE+f/S
# TgVWNCHbR2EYqTWayrGP69jMwtVD9BGGTWti1XjpvE6yKdO8H9nuRi3L+C6jYntf
# aEmBTbnTFEV+kRx1CNcpSb9os86CAUehZU1aRzQ6CQ/pjzCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUzNEYtOURE
# QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAkToz97fseHxNOUSQ5O/bBVSF+e6ggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOVRGuowIhgPMjAy
# MTEyMDEwNTQ5MzBaGA8yMDIxMTIwMjA1NDkzMFowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA5VEa6gIBADAKAgEAAgIYbgIB/zAHAgEAAgIRKDAKAgUA5VJsagIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAIrk+Rexm8bMnS+d+iYTWOgVx3IIX6Mk
# mvl5NKr4XxxG2ktaFpIp9j47EwnrEJmiOc+wq0WEWU+oFMhb/met21A17b5eOL/c
# LBQ4TEXGXqCsxuLjGVOzX5Hf+cLkZBQv5OoOfeJ4qxsc24WdbXGiD24mTY1G9wAE
# hh1WSMJmIZGlMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAFLT7KmSNXkwlEAAAAAAUswDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgyYCCVYIF
# qRgqEWPz5gzhL/ZeVQAT29xmO01G3UAC+tEwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCBr9u6EInnsZYEts/Fj/rIFv0YZW1ynhXKOP2hVPUU5IzCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABS0+ypkjV5MJRAAAA
# AAFLMCIEIPn8WBJ+AznSo18LyJTB8Xas1FwSkCpEYUBMCoNgn10pMA0GCSqGSIb3
# DQEBCwUABIIBAFqzGJfbt2sNChCJc6yeAqsCV1hetSAreTXcWkaCnwEquZge9AI8
# uVKo3pwQRWl5W6dJM2UPX/gfW2DX4V5exWfm7gQ/fDvm+9noFuDLaAzRZutQnDU3
# veab7EKUMZ+PV1dr9UPEmCbLh2B4qcPUTqeM67++lkONbsqm9ixOQYT0r5Q+3whb
# nJWGc6WIMb0MbuJRkcAlb1li/KAOp5rXlVji6rDnmOPSyMhN3aeaS6vfApaxYfM4
# lm62QHWPFCFhvwXn6bVv/5aY1dgFi62ogXksTqoWxDayZS+N41mF3WgY3MMKQcjQ
# V66hnQSsYxkJQrpwToVB8QyJdNvxX0ldAzg=
# SIG # End signature block
