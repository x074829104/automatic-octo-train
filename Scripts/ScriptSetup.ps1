#Requires -Version 3.0
Set-StrictMode -Version 3

<#
	Consumption Notes:
	* Designed to not be directly consumed by Service Model

	Implementation Notes:
	* This script should be isolated in the sense that it has no dependency on any other scripts besides being consumed by another script
#>

# Do not use Requires -RunAsAdministrator because this doesn't exist in PowerShell 3.0
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
{
	throw 'User is not an administrator or elevated and this is required to execute this script'
}

# Advanced Debugging - http://blogs.msdn.com/b/powershell/archive/2009/07/13/advanced-debugging-in-powershell.aspx
# about_Preference_Variables
$script:ErrorActionPreference = 'Stop' # When an error occurs forces execution to stop, behaving like a terminating error (Note: doesn't impact this script, only works on scripts\modules it loads)
# List of all error codes to be used by deployment
$script:ErrorCodes = [pscustomobject] @{ UpdateDefaultValues = 10; AddEventSource = 35; DeployApplicationService = 65; DeployDatabase = 85; DeployIntegration = 110; DeployProcessService = 135; InstallManagementReporter = 160; PostApplicationServiceConfiguration = 185; NewMRSetup = 210; UninstallManagementReporter = 235; RemoveMRSetup = 260; MRInstrumentation = 285; TestMRInstalled = 310; ImportMRDeploy = 335; DisplayMRDeploy = 360; RemoveMRModule = 385 }
$script:LoadedScriptSetup = $true
if (!(Get-Variable -Name logFilePath -Scope Script -ErrorAction SilentlyContinue))
{
	$script:logFilePath = Join-Path -Path $PSScriptRoot -ChildPath "MR_$(Get-Date -Format yyyyMMdd-HHmmss).log"
}

if (!(Get-Variable -Name Settings -Scope Script -ErrorAction SilentlyContinue))
{
	$script:Settings = $null
}

try
{
	$Host.PrivateData.VerboseForegroundColor = 'Cyan'
}
catch
{
	# Ignore if this fails
}

function Write-LogMessage
{
	Param
	(
		# Message to output
		$Message,

		# Indicates to show no timestamp in the message
		[switch]
		$NoTimestamp,

		# Indicates the message is a warning
		[switch]
		$Warning,

		# Indicates an error occured and it doesn't terminate script
		[switch]
		$Error,

		# Indicates the message is debug
		[switch]
		$Debug,

		# Timestamp format, ignored if -NoTimestamp is specified
		[string]
		$TimestampFormat = 'h:m:s.fff'
	)

	if(!$Message)
	{
		return
	}

	if(!$NoTimestamp)
	{
		$timestamp = Get-Date -Format $TimestampFormat
		$Message = "[$timestamp] $Message"
	}

	if($Error )
	{
		Write-Error -Message $Message -ErrorAction Continue 2>&1 | Out-Log
	}

	if($Debug)
	{
		Write-Debug -Message $Message -ErrorAction Continue  5>&1 | Out-Log
	}

	if($Warning )
	{
		Write-Warning -Message $Message 3>&1 | Out-Log
	}
	else
	{
		Write-Verbose -Message $Message -Verbose 4>&1 | Out-Log
	}
}

function Get-CertificateBasedEncryptionEngine
{
	[CmdletBinding()]
	Param
	(
		[ValidateNotNullOrEmpty()]
		[string]
		$encryptionCertificateId,

		[ValidateNotNullOrEmpty()]
		[string]
		$signingCertificateId
	)

	try
	{
		Write-LogMessage -Message 'Attempting to get CertificateBasedEncryptionEngine singleton instance.'
		return [Microsoft.Dynamics.Performance.Core.CertificateBasedEncryptionEngine]::GetInstance($encryptionCertificateId, $signingCertificateId)
	}
	catch
	{
		Write-LogMessage -Message 'CertificateBasedEncryptionEngine singleton not implemented. Attempting to create CertificateBasedEncryptionEngine using constructor.'
        Write-LogMessage -Message $_ -Warning
		return New-Object Microsoft.Dynamics.Performance.Core.CertificateBasedEncryptionEngine($encryptionCertificateId, $signingCertificateId)
	}
}

function Get-AXConnectionString
{
	[CmdletBinding()]
	[OutputType([string])]
	Param
	(
		[ValidateNotNullOrEmpty()]
		[string]
		$MRConnectionString,

		[ValidateNotNullOrEmpty()]
		[string]
		$DataEncryptionCertificateThumbprint,

		[string]
		$DataSigningCertificateThumbprint,

		[ValidateSet('Admin', 'Runtime')]
		$ConnectionType = 'Admin'
	)

	if (!$DataSigningCertificateThumbprint)
	{
		$DataSigningCertificateThumbprint = $DataEncryptionCertificateThumbprint
	}

	$query = "SELECT TOP 1 Settings FROM [Connector].[MapCategoryAdapterSettings] WHERE AdapterId = 'E3E10D70-FDAB-480C-952E-8397524F9236'"
	[xml]$adapterSettings = Invoke-SqlQuery -ConnectionString $MRConnectionString -Query $query -ResultReader (Get-ExecuteScalarReader)

	$nodes = $adapterSettings.SettingsCollection.ArrayOfSettingsValue.ChildNodes
	$serverNode = $nodes | Where-Object { ($_.FieldDefinition | Select-Object -Property Name).Name -eq 'DatabaseServer' }
	$databaseNode = $nodes | Where-Object { ($_.FieldDefinition | Select-Object -Property Name).Name -eq 'Database' }

	$axConnectionStringBuilder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
	
	if([bool]($($serverNode.value).PSobject.Properties.name -match "#text"))
	{
		$axConnectionStringBuilder.'Data Source' = $serverNode.Value.'#text'
	}
	else
	{
		$axConnectionStringBuilder.'Data Source' = $serverNode.Value
	}

	if([bool]($($databaseNode.value).PSobject.Properties.name -match "#text"))
	{
		$axConnectionStringBuilder.'Initial Catalog' = $databaseNode.Value.'#text'
	}
	else
	{
		$axConnectionStringBuilder.'Initial Catalog' = $databaseNode.Value
	}

	$axConnectionStringBuilder.'Integrated Security' = $false

	if ('Microsoft.Dynamics.Performance.Core.SerializablePassword' -as [type])
	{
		[Microsoft.Dynamics.Performance.Core.SerializablePassword]::SerializationEncryptionEngine = New-Object Microsoft.Dynamics.Performance.Core.CertificateBasedEncryptionEngine($DataEncryptionCertificateThumbprint, $DataSigningCertificateThumbprint)
	}

	[Microsoft.Dynamics.Performance.Core.DatabaseAccessControl]::SetPrivilegeDataSource($MRConnectionString)
	$priv = [Microsoft.Dynamics.Performance.Core.SchemaPrivilege]::Owner
	if($ConnectionType -ieq 'Runtime')
	{
		$priv = [Microsoft.Dynamics.Performance.Core.SchemaPrivilege]::Alter
	}

	$set = [Microsoft.Dynamics.Performance.Core.ManagedSchemaSet]::AX
	$axConnectionString = [Microsoft.Dynamics.Performance.Core.DatabaseAccessControl]::Instance.ApplyConnectionPrivilege($axConnectionStringBuilder.ConnectionString, $set, $priv)

	return $axConnectionString
}

function Test-PropertyExists
{
	[CmdletBinding()]
	[OutputType([bool])]
	Param
	(
		[Parameter(Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNull()]
		$InputObject,

		[Parameter(Position = 1, ValueFromPipeline = $false)]
		[string]
		[ValidateNotNullOrEmpty()]
		$PropertyName
	)

	process
	{
		$properties = Get-PropertiesOnObject -InputObject $InputObject
		if($properties -and $properties.Count -ge 0)
		{
			return $properties -contains $PropertyName
		}
		else
		{
			return $false
		}
	}
}

function Get-ValueFromXPath
{
	[CmdletBinding()]
	Param
	(
		[xml]
		[ValidateNotNull()]
		$serviceModelXml,

		[string]
		[ValidateNotNullOrEmpty()]
		$XPath,

		[string]
		[ValidateNotNullOrEmpty()]
		$ParamName
	)

	$result = Select-Xml $serviceModelXml -XPath $XPath | Where { $_.Node.Name -eq $ParamName } | Select -First 1
	if ($result)
	{
		if([bool]($($result.Node.Value).PSobject.Properties.name -match "#text"))
		{ 
			return $result.Node.Value.'#text'
		}

		return $result.Node.Value
	}

	return $null
}

function Get-PropertiesOnObject
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0)]
		[ValidateNotNull()]
		$InputObject
	)

	return Get-Member -InputObject $InputObject | Where-Object -FilterScript { $_.MemberType -like '*Property' } | ForEach-Object -Process { $_.Name }
}

function Update-ValueFromConfig
{
	[CmdletBinding()]
	Param
	(
		[ValidateNotNull()]
		$Settings,

		[string]
		[ValidateNotNullOrEmpty()]
		$PropertyName,

		[Parameter(ParameterSetName = 'MRDefault')]
		[string]
		[ValidateNotNullOrEmpty()]
		$MRDefaultValueName,

		[Parameter(ParameterSetName = 'MRDefault')]
		[ref]
		$MRDefaultValues,

		[Parameter(ParameterSetName = 'UpdateObject')]
		[ref]
		$UpdateObject,

		[Parameter(ParameterSetName = 'UpdateObject')]
		[string]
		[ValidateNotNullOrEmpty()]
		$UpdateObjectName,

		[scriptblock]
		[ValidateNotNull()]
		$WarningCondition = { $true },

		[switch]
		$IsBoolean,

		[switch]
		$HideValue,

		[switch]
		$Mandatory,

		[string]
		$XPath = '//Configuration/Setting',

		# Used only for removal scenario - we need to lookup the secret during script runtime
		[switch]
		$ResolveSecret
	)

	$value = $null
	if ($Settings -is [PSCustomObject])
	{
		if (Test-PropertyExists -InputObject $Settings -PropertyName $PropertyName)
		{
			$value = [string]($Settings | select -ExpandProperty $PropertyName)
		}
	}
	elseif ($Settings -is [xml])
	{
		$value = Get-ValueFromXPath -ServiceModelXml $Settings -XPath $XPath -ParamName $PropertyName
	}
	else
	{
		throw "Settings must either be [PSCustomObject] (config) or [xml] (ServiceModelXml)."
	}

	$isUpdateObjectParameterSet = $PSCmdlet.ParameterSetName -eq 'UpdateObject'
	if($value -ne $null)
	{
		if($IsBoolean)
		{
			$result = $false
			if(!([bool]::TryParse($value, [ref]$result)))
			{
				Write-LogMessage -Message "Unable to parse '$value' to boolean for config setting '$PropertyName', defaulted to false" -Warning
			}

			$value = $result
		}

		$valueToWrite = $value
		if($HideValue)
		{
			$valueToWrite = '**********'
		}

		# Typically only used in remove scenario - for the uninstall script
		if($ResolveSecret -and $value -ilike 'vault://*')
		{
			$keyVaultModule = Join-Path -Path $PSScriptRoot -ChildPath "KeyVault.psm1"
			$keyVaultName = $Settings.'Infrastructure.AzureKeyVaultName'
			$appId = $Settings.'Infrastructure.AzureKeyVaultAppId'
			$tenantId = $Settings.'Infrastructure.AzureKeyVaultTenantId'
			$thumprint = $Settings.'Infrastructure.AzureKeyVaultCertThumbprint'
			Import-Module $keyVaultModule -DisableNameChecking -ArgumentList ($keyVaultName, $appId, $tenantId, $thumprint)

			$value = Get-KeyVaultSecret -VaultUri $value
		}

		if($isUpdateObjectParameterSet)
		{
			$UpdateObject.Value = $value
			# UpdateObject is used outside of commands
			Write-LogMessage -Message "$UpdateObjectName set to '$valueToWrite'"
		}
		else
		{
			$MRDefaultValues.Value.$MRDefaultValueName = $value
			Write-LogMessage -Message "$MRDefaultValueName set to '$valueToWrite'"
		}
	}
	elseif($Mandatory)
	{
		throw "Property $PropertyName does not exist in settings"
	}
	elseif(&$WarningCondition)
	{
		Write-LogMessage -Message "$PropertyName not supplied" -Warning
	}
}

function Test-CommandExists
{
	[CmdletBinding()]
	[OutputType([bool])]
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$CommandName,

		[string]
		$Message = "$CommandName is not available"
	)

	$commandExists = Get-Command -Name $CommandName -Module $ModuleName -ErrorAction SilentlyContinue
	$result = $commandExists -ne $null
	if(!$result -and $Message)
	{
		Write-LogMessage -Message $Message -Warning
	}

	return $result
}

function Remove-InvalidParameters
{
	[CmdletBinding()]
	[OutputType([Hashtable])]
	Param
	(
		[ValidateNotNull()]
		$Command,

		[Hashtable]
		$Parameters,

		[switch]
		$SuppressWarnings,

		[string]
		$ModuleName
	)

	if($Parameters -eq $null -or $Parameters.Count -eq 0)
	{
		return $Parameters
	}

	[Management.Automation.CommandInfo]$realCommand = $null
	[string]$commandName = ''
	if ($Command -isnot [Management.Automation.CommandInfo])
	{
		$commandName = $Command
		$realCommand = Get-Command -Name $Command -Module:$ModuleName | Select-Object -First 1
	}
	else
	{
		$realCommand = $Command
		$commandName = $realCommand.Name
	}

	# Known limitation: can't handle parameter types being different
	$availableParameters = $realCommand.Parameters.Keys
	$removeParameters = $Parameters.Keys | Where-Object -FilterScript { $_ -notin $availableParameters }
	if($removeParameters)
	{
		foreach($parameter in $removeParameters)
		{
			$Parameters.Remove($parameter)
			if(!$SuppressWarnings)
			{
				Write-LogMessage -Message "Removed '$parameter' parameter from executing on '$commandName' command" -Warning
			}
		}
	}

	return $Parameters
}

function Get-MRFilePaths
{
	[CmdletBinding()]
	Param
	(
		[switch]
		$SuppressError
	)

	$paths = [pscustomobject]@{
		Server    = ''
		ClickOnce = ''
		Connector = ''
		Console = ''
		InstallLocation = ''
		MRDeploy  = ''
		ApplicationService = ''
		ApplicationServiceConnectionsConfig = ''
		ApplicationServiceSettingsConfig = ''
		ServicesConnectionsConfig = ''
		ServicesSettingsConfig = ''
		Services = ''
	}

	$registryView = [Microsoft.Win32.RegistryView]::Default
	if([Environment]::Is64BitOperatingSystem)
	{
		# If OS is x64, always force x64 registry
		$registryView = [Microsoft.Win32.RegistryView]::Registry64
	}

	$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $registryView)
	$mrServerRegKey = $baseKey.OpenSubKey('Software\Microsoft\Dynamics\ManagementReporter\21\Server')
	[string]$mrInstallLocation = $null
	if(!$mrServerRegKey)
	{
		# See if the MSI is installed and pull the InstallLocation from that, fail-safe if the registry gets messed up
		$product = Get-MRServerInstallProduct
		if(!$product)
		{
			if($SuppressError)
			{
				return $null
			}
			else
			{
				throw 'MR server is not installed'
			}
		}
		else
		{
			$mrInstallLocation = $product.InstallLocation
		}
	}
	else
	{
		$mrInstallLocation = $mrServerRegKey.GetValue('InstallLocation')
	}

	$mrServerPath = Join-Path -Path $mrInstallLocation -ChildPath 'Server'
	$servicesPath = Join-Path -Path $mrServerPath -ChildPath '\Services'
	$clickOncePath = Join-Path -Path $mrServerPath -ChildPath 'ClickOnceClient'
	$connectorPath = Join-Path -Path $mrServerPath -ChildPath '\Connector'
	$consolePath = Join-Path -Path $mrServerPath -ChildPath '\Console'
	$mrDeployPath = Join-Path -Path $mrServerPath -ChildPath 'MRDeploy'
	$appServFolderPath = Join-Path -Path $mrServerPath -ChildPath 'ApplicationService'
	$servicesConnectionConfig = Join-Path -Path $servicesPath -ChildPath 'MRServiceHost.connections.config'
	$servicesSettingsConfig = Join-Path -Path $servicesPath -ChildPath 'MRServiceHost.settings.config'
	$applicationConnectionConfig = Join-Path -Path $appServFolderPath -ChildPath 'bin\MRServiceHost.connections.config'
	$applicationServiceSettingsConfig = Join-Path -Path $appServFolderPath -ChildPath 'bin\MRServiceHost.settings.config'

	$paths.ApplicationService = $appServFolderPath
	$paths.InstallLocation = $mrInstallLocation
	$paths.Server = $mrServerPath
	$paths.Services = $servicesPath
	$paths.ClickOnce = $clickOncePath
	$paths.Connector = $connectorPath
	$paths.Console = $consolePath
	$paths.MRDeploy = $mrDeployPath
	$paths.ApplicationServiceConnectionsConfig = $applicationConnectionConfig
	$paths.ApplicationServiceSettingsConfig = $applicationServiceSettingsConfig
	$paths.ServicesConnectionsConfig = $servicesConnectionConfig
	$paths.ServicesSettingsConfig = $servicesSettingsConfig
	return $paths
}

function Get-MRServerInstallProduct
{
	$MRServerInstallProductName = "Management Reporter 2012 Server"

	return Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
		Select-Object Name, DisplayName, DisplayVersion, InstallDate, InstallLocation, UninstallString |
		Where-Object {$_.DisplayName -ne $null -and $_.DisplayName.Contains($MRServerInstallProductName)}
}

function ReplaceAssembly
{
	[CmdletBinding()]
	Param
	(
		[string]
		$AssemblyFileName,

		[string]
		$SourcePath,

		[string]
		$TargetPath
	)

	Write-LogMessage -Message "Replacing assembly started: $AssemblyFileName."
	Write-LogMessage -Message "Target location: $TargetPath, Source location: $SourcePath."

	$sourceFilePath = Join-Path -Path $SourcePath -ChildPath $AssemblyFileName

	if (Test-Path $sourceFilePath)
    {
		$sourceFile = Get-ChildItem -File $sourceFilePath
		$sourceVersion = [version]$sourceFile.VersionInfo.FileVersion
		Write-LogMessage -Message "Source file version: $sourceVersion."

		$targetFiles = Get-ChildItem -Path $TargetPath -Filter $AssemblyFileName -Recurse
        foreach ($targetFile in $targetFiles)
		{
			if($targetFile -ne $null)
			{
				$targetVersion = [version]$targetFile.VersionInfo.FileVersion
				Write-LogMessage -Message "Target file $($targetFile.FullName) version: $targetVersion."
				if($targetVersion -lt $sourceVersion)
				{
					Copy-Item -Path $sourceFile.FullName -Destination $targetFile.FullName -Force
					Write-LogMessage -Message "Assembly replaced successfully."
				}
			}
		}
	}
	else
	{
		Write-LogMessage -Message "No matching assembly found at $sourceFilePath." -Warning
	}

	Write-LogMessage -Message "Completed replacing assembly: $AssemblyFileName."
}

function Uninstall-MRServer
{
	[CmdletBinding()]
	Param
	(
		[switch]
		$SuppressWarning,

		[string]
		$WarningMessageBeforeUninstall
	)

	Write-LogMessage -Message 'Removing MR server install'
	$product = Get-MRServerInstallProduct
	if(!$product)
	{
		Write-LogMessage -Message 'MR server install was not found' -Warning:(!$SuppressWarning)
		return
	}

	if($WarningMessageBeforeUninstall)
	{
		Write-LogMessage -Message $WarningMessageBeforeUninstall -Warning
	}

	$applicationName = $product.DisplayName
	Write-LogMessage -Message "Removing $applicationName" -Debug

	$uninstallPath = Join-Path -Path $product.InstallLocation -ChildPath "MRServer_x64.msi"
	$result = Start-Process -PassThru -Wait -FilePath msiexec -ArgumentList /norestart, /quiet, /uninstall, $uninstallPath

	if($result.ExitCode -eq 0)
	{
		Write-Output -InputObject "$applicationName was successfully uninstalled"
	}
	else
	{
		throw "Failed to uninstall $applicationName, MSIEXEC exited with error code $($result.ExitCode)"
	}
}

function Get-MRInstallerName
{
	[CmdletBinding()]
	Param
	(
		[Parameter(ParameterSetName = 'Server')]
		[switch]
		$Server,

		[Parameter(ParameterSetName = 'Client')]
		[switch]
		$Client
	)

	[string]$architecture = $null
	if([System.Environment]::Is64BitOperatingSystem)
	{
		$architecture = '64'
	}
	else
	{
		$architecture = '32'
	}

	[string]$productName = $null
	if($Server)
	{
		$productName = 'Server'
	}
	elseif($Client)
	{
		$productName = 'Client'
	}

	return "MR$($productName)_x$($architecture).msi"
}

function Test-MRInstalled
{
	$mrPaths = Get-MRFilePaths -SuppressError
	if(!$mrPaths)
	{
		Write-LogMessage -Message 'No MR server install was detected'
	}

	return $mrPaths -ne $null
}

function Import-MRDeployModule
{
	# Import module before use, it's safe to import multiple times
	Write-LogMessage -Message 'Importing module MRDeploy'
	$mrPaths = Get-MRFilePaths
	Import-Module -Name $mrPaths.MRDeploy -Force
}

function Show-MRDeployVersion
{
	$module = Get-Module 'MRDeploy'
	if($module)
	{
		Write-LogMessage -Message "$($module.Name) version = $($module.Version)"
	}
	else
	{
		Write-LogMessage -Message 'MRDeploy is not imported' -Warning
	}
}

function Copy-MREventLogs
{
	[CmdletBinding()]
	Param
	(
		[string]
		$FolderForLogs,

		[ValidateNotNull()]
		[Datetime]
		$StartRange
	)

	if($FolderForLogs)
	{
		if(!(Test-Path $FolderForLogs))
		{
			Write-LogMessage -Warning "Folder for log files $FolderForLogs doesn't exist.";
			return
		}

		$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
		$providerName = 'Management Reporter 2012 Services'
		# Bug in PowerShell if you query for a provider that doesn't exist you get an error 'The parameter is incorrect'. Even SilentlyContinue won't suppress the error
		$providerFound = Get-WinEvent -ProviderName $providerName -ErrorAction SilentlyContinue
		if($providerFound)
		{
			$servicesEventLogs = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=$providerName; StartTime=$StartRange} -ErrorAction SilentlyContinue | % { @{'Time'=$_.TimeCreated.ToString('hh:mm:ss tt'); 'Level'=$_.LevelDisplayName; 'Message'=$_.Message} } | Format-Table -AutoSize -Wrap -HideTableHeaders | Out-String
			if($servicesEventLogs)
			{
				$serviceEventLogPath = Join-Path -Path $FolderForLogs  -ChildPath "Services_$timestamp.log"
				"$providerName Events:" >> $serviceEventLogPath
				$servicesEventLogs >> $serviceEventLogPath
			}
			else
			{
				Write-LogMessage "No event logs found for $providerName"
			}
		}
		else
		{
			Write-LogMessage -Warning "Provider is not installed for $providerName"
		}

		$etwProviders = Get-WinEvent -ListLog 'Microsoft-Dynamics-MR-*' -ErrorAction SilentlyContinue
		if($etwProviders)
		{
			foreach($etwProvider in $etwProviders)
			{
				$etwEvents = Get-WinEvent -FilterHashtable @{'LogName'=($etwProvider.LogName); StartTime=$StartRange} -ErrorAction SilentlyContinue | % { @{'Time'=($_.TimeCreated.ToString('hh:mm:ss tt')); 'Level'=($_.LevelDisplayName); 'Message'=($_.Message); 'Properties'=($_.Properties | % { $_.Value } | Format-Table -AutoSize -HideTableHeaders -Wrap | Out-String)} } | Format-Table -AutoSize -Wrap -HideTableHeaders | Out-String
				if($etwEvents)
				{
					$etwEventLogPath = Join-Path -Path $FolderForLogs -ChildPath "$($etwProvider.LogName -replace '/', '_')_$timestamp.log"
					"$($etwProvider.LogName) Events:" >> $etwEventLogPath
					$etwEvents >> $etwEventLogPath
				}
				else
				{
					Write-LogMessage "No event logs found for $($etwProvider.LogName)"
				}
			}
		}
	}
	elseif (!$FolderForLogs)
	{
		Write-LogMessage -Warning 'No log file path was specified, skipping dump of MR event log files.'
	}
}

function Copy-DeploymentLogFile
{
	[CmdletBinding()]
	Param
	(
		[ValidateNotNullOrEmpty()]
		[string]
		$DeploymentLogPath = "$env:ProgramData\Microsoft Dynamics ERP\Management Reporter\Logs",

		[string]
		$FolderForLogs,

		[ValidateNotNull()]
		[Datetime]
		$StartRange,

		[ValidateNotNull()]
		[Datetime]
		$EndRange = (Get-Date)
	)

	if($FolderForLogs)
	{
		if(!(Test-Path $DeploymentLogPath))
		{
			Write-LogMessage -Warning "Deployment logs path $DeploymentLogPath doesn't exist.";
			return;
		}

		if(!(Test-Path $FolderForLogs))
		{
			Write-LogMessage -Warning "Folder for log files $FolderForLogs doesn't exist.";
			return;
		}

		[System.IO.FileInfo[]] $logFiles = Get-ChildItem -Recurse -Path $DeploymentLogPath -Include *.log | Where-Object {$_.CreationTime -ge $StartRange -and $_.CreationTime -le $EndRange}
		if($logFiles -eq $null -or $logFiles.Length -eq 0)
		{
			Write-LogMessage -Warning "No log files found under $DeploymentLogPath for range $StartRange to $EndRange";
			return;
		}

		Write-LogMessage -Message "Dumping MR Deployment logs to $FolderForLogs"
		foreach($logFile in $logFiles)
		{
			if((Get-Item $logFile).Length -gt 0)
			{
				Copy-Item -Path $logFile -Destination $FolderForLogs -Force
			}
		}
	}
	elseif (!$FolderForLogs)
	{
		Write-LogMessage -Warning 'No log file path was specified, skipping dump of MR deployment files.'
	}
}

function Write-FormatListToLogFilePath
{
	Param
	(
		[string]
		$Message,

		$MessageObject,

		[string]
		[ValidateNotNullOrEmpty()]
		$LogFilePath,

		[switch]
		$PassThru
	)

	$stringBuilder = New-Object System.Text.StringBuilder
	if($Message)
	{
		$localExecutionResult = Add-Content -Path $LogFilePath -Value $Message -Force
		$localExecutionResult = $stringBuilder.AppendLine($Message)
	}

	if($MessageObject -eq $null)
	{
		$messageString = '<NULL>'
	}
	elseif($MessageObject -is [string])
	{
		$messageString = $MessageObject
	}
	else
	{
		$messageString = $MessageObject | Format-List * -Force -Expand Both | Out-String
	}

	$localExecutionResult = Add-Content -Path $LogFilePath -Value $messageString -Force
	$localExecutionResult = $stringBuilder.AppendLine($messageString)
    return $stringBuilder.ToString()
}


function Assert-MRUpgradeIsScriptBlock
{
	[CmdletBinding()]
	[OutputType([scriptblock])]
	Param
	(
		$ScriptBlock
	)

	if($ScriptBlock -eq $null)
	{
		throw 'ScriptBlock cannot be null.'
	}
	elseif($ScriptBlock -is [scriptblock])
	{
		return $ScriptBlock
	}
	elseif($ScriptBlock -is [string])
	{
		return [System.Management.Automation.ScriptBlock]::Create($ScriptBlock)
	}
	else
	{
		throw "Argument was not a scriptblock or a value that could be converted to a scriptblock, it was of type '$($ScriptBlock.GetType())'"
	}
}

function Invoke-MRUpgradePSBackgroundJob
{
	Param
	(
		[ValidateNotNull()]
		$ExecuteScript,

		[string]
		$JobName,

		[string]
		$JobErrorDescription = 'Background job failed',

		[PSObject]
		$ScriptBlockParameters
	)

	$execute = Assert-MRUpgradeIsScriptBlock -ScriptBlock $ExecuteScript
	$job = Start-Job -ScriptBlock $execute -Name:$JobName -ArgumentList $ScriptBlockParameters
	try
	{
		Write-LogMessage -Message "Before receiving upgrade background job: $($job.Name). Job state is: $($job.State)"
		# if the backgroup job failed with an exception, the Receive-Job in the main thread may not get executed.
		Receive-Job -Job $job -Wait -WriteJobInResults
		Write-LogMessage -Message "Received upgrade background job: $($job.Name). Job state is: $($job.State)"
	}
	catch
	{
		Write-LogMessage -Message "Got exception while executing receive-job."
		if($JobName -ne 'LogErrorToTelemetry')
		{
			Write-ErrorDetail -ErrorThrown $_
		}
		else
		{
			# Just write error if LogErrorToTelemetry failed, otherwise we get an infinite loop
			Write-Error $_ -ErrorAction Continue
		}

		throw $JobErrorDescription
	}
	finally
	{
		Write-LogMessage -Message "Try to remove upgrade background job: $($job.Name). Job state is: $($job.State)"
		if($null -ne $job)
		{
			Remove-Job -Job $job -Force
		}
		Write-LogMessage -Message "Completed trying to remove upgrade background job: $($job.Name). Job state is: $($job.State)"
	}
}

function Log-ErrorToTelemetry
{
	Param
	(
        [string]
        $id,

        [string]
        $component,

        [string]
        $errorMessage,

        [string]
        $exceptionMessage,

        [string]
        $exceptionSource,

        [string]
        $exceptionType,

        [string]
        $stackTrace,

        [string]
        $failureBucketId
	)

    # Replace ", quotation marks, with a double quotation mark to avoid powershell split a string with quoted content in to two or more strings
    if($id -ne $null)
    {
        $id = $id.replace('"','""')
    }

    if($component -ne $null)
    {
        $component = $component.replace('"','""')
    }

    if($errorMessage -ne $null)
    {
        $errorMessage = $errorMessage.replace('"','""')
    }

    if($exceptionMessage -ne $null)
    {
        $exceptionMessage = $exceptionMessage.replace('"','""')
    }

    if($exceptionSource -ne $null)
    {
        $exceptionSource = $exceptionSource.replace('"','""')
    }

    if($exceptionType -ne $null)
    {
        $exceptionType = $exceptionType.replace('"','""')
    }

    if($stackTrace -ne $null)
    {
        $stackTrace = $stackTrace.replace('"','""')
    }

    if($failureBucketId -ne $null)
    {
        $failureBucketId = $failureBucketId.replace('"','""')
    }

	$installPaths = Get-MRFilePaths
	$instrumentationDll = Join-Path -Path $installPaths.Services -ChildPath 'Microsoft.Dynamics.Reporting.Instrumentation.dll'
	$deploymentDll = Join-Path -Path $installPaths.Services -ChildPath 'Microsoft.Dynamics.Performance.Common.Server.dll'
	$logErrorToTelemetryScript = $null

	if(Test-Path -Path $deploymentDll)
	{
		$logErrorToTelemetryScript = @"
Add-Type -Path "$instrumentationDll"
Add-Type -Path "$deploymentDll"
[void]([Microsoft.Dynamics.Reporting.Instrumentation.LoggerEventSource]::EventWriteLoggerErrorEvent([Microsoft.Dynamics.Performance.Common.Server.Deployment.DeploymentLog]::DeployLogTraceSource, "$id", "$component", "$errorMessage", "$exceptionMessage", "$exceptionSource", "$exceptionType", "$stackTrace", "$failureBucketId"))
"@
	}
	else
	{
		$deploymentDll = Join-Path -Path $installPaths.Console -ChildPath 'Microsoft.Dynamics.Performance.Deployment.Common.dll'

		$logErrorToTelemetryScript = @"
Add-Type -Path "$instrumentationDll"
Add-Type -Path "$deploymentDll"
[void]([Microsoft.Dynamics.Reporting.Instrumentation.LoggerEventSource]::EventWriteLoggerErrorEvent([Microsoft.Dynamics.Performance.Deployment.Common.Logging.DeploymentLog]::DeployLogTraceSource, "$id", "$component", "$errorMessage", "$exceptionMessage", "$exceptionSource", "$exceptionType", "$stackTrace", "$failureBucketId"))
"@
	}

	try
	{
		Invoke-MRUpgradePSBackgroundJob -ExecuteScript $logErrorToTelemetryScript -JobName "LogErrorToTelemetry" -JobErrorDescription "LogErrorToTelemetry job failed"
	}
	catch
	{
		# We cannot let telemetry logging fail the process
		Write-Error -Message "Failed to write error detail to Telemetry, check log for details instead." -ErrorAction Continue
	}
}

function Write-ErrorDetail
{
	Param
	(
		# The error to write out
		$ErrorThrown,

		# The path to the log file to write the error to
		[string]
		$LogPath,

		# If present, will write to console in addition to writing to log
		[switch]
		$WriteToConsole,

		# If present, will return the string containing the full error details written to the log
		[switch]
		$PassThru
	)

	if (!$LogPath)
	{
		$LogPath = $script:logFilePath
	}

	[string]$fullMessage = Write-FormatListToLogFilePath -Message '[ERROR] Terminating error encountered, deployment may not be complete!!!' -MessageObject $ErrorThrown -LogFilePath $LogPath -PassThru:$PassThru
	if(Get-Member -inputobject $ErrorThrown -name "Exception" -Membertype Properties)
	{
		if($ErrorThrown.Exception -ne $null)
		{
			$lookAtException = $ErrorThrown.Exception
			# Sometimes the exception can have more details if you do a Format-List on it
			$fullMessage += Write-FormatListToLogFilePath -Message 'Exception details:' -MessageObject $lookAtException -LogFilePath $LogPath -PassThru:$PassThru
			if($lookAtException -is [System.Management.Automation.RuntimeException])
			{
				# Information will be stored in ErrorRecord
				$lookAtException = $lookAtException.ErrorRecord.Exception
			}

			# If RemoteException, it likely came from Invoke-PSAppDomain
			if($lookAtException -is [System.Management.Automation.RemoteException])
			{
				# SerializedRemoteInvocationInfo will have the true location where the error got thrown
				$fullMessage += Write-FormatListToLogFilePath -Message 'Location where error got thrown:' -MessageObject $lookAtException.SerializedRemoteInvocationInfo -LogFilePath $LogPath -PassThru:$PassThru
				# SerializedRemoteException will have the exception thrown but depending on what happened the info might not be useful
				$fullMessage += Write-FormatListToLogFilePath -Message 'Serialized exception:' -MessageObject $lookAtException.SerializedRemoteException -LogFilePath $LogPath -PassThru:$PassThru
				# The SerializedRemoteException will contain the InnerException to navigate through (if any)
				$lookAtException = Get-InnerException -Exception ($lookAtException.SerializedRemoteException)
			}
			else
			{
				$availableMembers = $lookAtException | Get-Member | % { $_.Name }
				if('InvocationInfo' -in $availableMembers)
				{
					$fullMessage += Write-FormatListToLogFilePath -Message 'Location where error got thrown:' -MessageObject $lookAtException.InvocationInfo -LogFilePath $LogPath -PassThru:$PassThru
				}
				else
				{
					# If a throw was done outside a function (in this script) it can lose its InvocationInfo so the high-level object needs to be looked at
					$fullMessage += Write-FormatListToLogFilePath -Message 'Location where error got thrown:' -MessageObject $ErrorThrown.InvocationInfo -LogFilePath $LogPath -PassThru:$PassThru
				}

				$lookAtException = Get-InnerException -Exception $lookAtException
			}

			if($lookAtException -ne $null)
			{
				if($lookAtException -is [System.AggregateException])
				{
					# The base exception thrown by PowerShell can't be an AggregateException because PowerShell wraps it but the InnerException can be an AggregateException
					$fullMessage += Write-FormatListToLogFilePath -Message 'Aggregate Exception:' -MessageObject $lookAtException -LogFilePath $LogPath -PassThru:$PassThru
					$aggregateExceptionCount = 1
					foreach($innerException in $lookAtException.InnerExceptions)
					{
						$fullMessage += Write-FormatListToLogFilePath -Message "Inner Exception $($aggregateExceptionCount):" -MessageObject $innerException -LogFilePath $LogPath -PassThru:$PassThru
						$aggregateExceptionCount++
					}
				}
				else
				{
					while($lookAtException -ne $null)
					{
						$fullMessage += Write-FormatListToLogFilePath -Message 'Inner Exception:' -MessageObject $lookAtException -LogFilePath $LogPath -PassThru:$PassThru
						$lookAtException = Get-InnerException -Exception $lookAtException
					}
				}
		    }

			try
			{
				$exceptionMessage = $null
				$exceptionType = $null
				$exception = $ErrorThrown.Exception;
				if($exception -ne $null)
				{
					if($ErrorThrown.PSobject.Properties['Message'])
					{
						$exceptionMessage = $ErrorThrown.PSobject.Properties['Message']
					}
					elseif($exception.Message -ne $null)
					{
						$exceptionMessage = $exception.Message
					}

					$exceptionType = $exception.GetType().Name
				}

				Write-Warning -Message 'Writing full error detail to telemetry, check event logs for detail.'
				Log-ErrorToTelemetry -id $null -component "ScriptSetup.ps1" -errorMessage $fullMessage -exceptionMessage $exceptionMessage -exceptionSource $ErrorThrown.TargetObject -exceptionType $exceptionType -stackTrace $ErrorThrown.ScriptStackTrace -failureBucketId $null
			}
			catch
			{
				Write-Error -Message "Failed to write error detail to Telemetry" -ErrorAction Continue
			}
		}
	}

	if ($WriteToConsole)
	{
		Write-Error -Message $fullMessage -ErrorAction Continue
	}

	if ($PassThru)
	{
		return $fullMessage
	}
}

function Get-InnerException
{
	[CmdletBinding()]
	[OutputType([Exception])]
	Param
	(
		$Exception
	)

	if($Exception -and (Get-Member -InputObject $Exception -MemberType 'Property' -Name 'InnerException'))
	{
		return $Exception.InnerException
	}

	return $null
}

function Test-FunctionExists
{
	[CmdletBinding()]
	[OutputType([bool])]
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$Name
	)

	$function = Get-Item function:$Name -ErrorAction SilentlyContinue
	return $function -ne $null
}

# ErrorHandled is used to prevent multiple errors from being outputted
$ErrorHandled = $false
function Invoke-ExecutionScript
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$ExecutionScript,

		[switch]
		$ReturnLastOutput
	)

	# Set-Item function:fnName is a HACK from Jason Shirk - assinging to anoymous scriptblock prevents all the command's content from spilling out into error message
	$fnName = $ExecutionScript.Name
	if(Test-FunctionExists -Name $fnName)
	{
		# If there was a duplicate this prevents collision
		Remove-Item -Path function:$fnName
	}

	Set-Item -Path function:$fnName -Value ($ExecutionScript.Script)

	# Streams redirection (*>&1) - 1. http://blogs.technet.com/b/heyscriptingguy/archive/2014/03/30/understanding-streams-redirection-and-write-host-in-powershell.aspx
	# 2. http://social.technet.microsoft.com/wiki/contents/articles/13726.the-concept-of-input-output-streams-in-powershell.aspx
	# 3. unsupported workaround - http://social.technet.microsoft.com/Forums/windowsserver/en-US/6c8a9e5d-3103-4f94-af15-75b309fc8360/redirecting-mixed-powershell-pipeline-and-console-object-output?forum=winserverpowershell
	# 4. https://connect.microsoft.com/feedback/ViewFeedback.aspx?FeedbackID=297055&SiteID=99

	$executeCommand = {
		&$fnName `
			*>&1 | Out-Log
	}

	Write-LogMessage -Message "Executing '$fnName'"
	try
	{
		if($ReturnLastOutput)
		{
			$global:exOutput = $null
			$executeCommand = {
				&$fnName `
				*>&1 | Tee-Object -Variable 'global:exOutput' | Out-Log
			}

			& $executeCommand
			Write-LogMessage -Message "Finished executing '$fnName'"

			# return the last output
			return $global:exOutput[-1]
		}
		else
		{
			& $executeCommand
			Write-LogMessage -Message "Finished executing '$fnName'"
		}
	}
	catch
	{
		$errorCaught = $Error[0]
		if(!$script:ErrorHandled)
		{
			$script:ErrorHandled = $true
			if($script:logFilePath)
			{
				try
				{
					Write-ErrorDetail -ErrorThrown $errorCaught -LogPath $script:logFilePath
				}
				catch
				{
					Write-FormatListToLogFilePath -Message 'Failed to output error' -MessageObject $Error[0] -LogFilePath $script:logFilePath
					# Eat the exception
				}
			}

			[int]$exitCode = $ExecutionScript.ErrorCode
			[string]$exitMessage = "Failed executing $($ExecutionScript.Name)"
			if($ExecutionScript.ErrorCodeHandler -ne $null -and $ExecutionScript.ErrorCodeHandler.ToString().Length -gt 0)
			{
				$errorCodeFromHandler = & $ExecutionScript.ErrorCodeHandler $errorCaught
				# Testing to make sure the object return is not null and it has properties for ErrorCode and ErrorMessage
				if($errorCodeFromHandler -and ($errorCodeFromHandler | select -First 1 | % { $g = Get-Member -InputObject $_ | % { $_.Name }; @('ErrorCode', 'ErrorMessage') -in $g }))
				{
					$exitCode = $errorCodeFromHandler.ErrorCode
					$exitMessage = $errorCodeFromHandler.ErrorMessage
				}
			}

			$exitCodeObject = [pscustomobject] @{'ExitCode'=$exitCode;'Message'=$exitMessage;}
			Write-Output $exitCodeObject
		}

		throw
	}
}

function New-ScriptExecution
{
	[CmdletBinding()]
	Param
	(
		[scriptblock]
		[ValidateNotNull()]
		$Script,

		[string[]]
		$Functions,

		[string]
		[ValidateNotNullOrEmpty()]
		$Name,

		[switch]
		$UseAppDomain,

		[int]
		$ErrorCode = 1,

		[scriptblock]
		$ErrorCodeHandler
	)

	$execution = New-Module -ScriptBlock {
		[scriptblock]$Script = {}
		[string[]]$Functions = @()
		[string]$Name = ''
		[bool]$UseAppDomain = $false
		[int]$ErrorCode = 1
		[scriptblock]$ErrorCodeHandler = {}

		Export-ModuleMember -Function * -Variable *
	} -AsCustomObject

	$execution.Name = $Name
	$execution.Script = $Script
	$execution.UseAppDomain = $UseAppDomain.IsPresent
	$execution.ErrorCode = $ErrorCode
	if($Functions)
	{
		$execution.Functions = $Functions
	}

	if($ErrorCodeHandler)
	{
		$execution.ErrorCodeHandler = $ErrorCodeHandler
	}

	return $execution
}

function Set-LogPath
{
	[CmdletBinding()]
	Param
	(
		# Full path for log file. If defined, LogDir and LogFileName are not used.
		[string]
		$FullLogPath,

		# Path to directory in which to place log file. Not used if FullLogPath is defined.
		[string]
		$LogDir,

		# Name to embed in full log file name.
		[string]
		$LogFileName
	)

	if($FullLogPath)
	{
		$script:logFilePath = $FullLogPath
	}
	elseif($LogDir)
	{
		$script:logFilePath = Join-Path -Path $LogDir -ChildPath "MR_$($LogFileName)_$(Get-Date -Format yyyyMMdd-HHmmss).log"
	}
}

filter Out-Log
{
	if($script:logFilePath)
	{
		$fileOutput = $null
		# Teeing to a variable to prevent 'The process cannot access the file _ because it is used by another process'
		$_ | Tee-Object -Variable fileOutput | Out-Host

		if($fileOutput)
		{
			$retryOutFile = 5
			while($retryOutFile -gt 0)
			{
				try
				{
					$retryOutFile--
					$fileOutput | Out-File -FilePath $script:logFilePath -Append -Force -NoClobber
					$retryOutFile = 0
				}
				catch
				{
					if($retryOutFile -eq 0)
					{
						# Write warning on last retry
						$errorMessage = $_ | Out-String
						Write-Warning $errorMessage
					}
				}
			}
		}
	}
	else
	{
		$_ | Out-Host
	}
}

function Write-EnvironmentDataToLog
{
	$processInformation = [Diagnostics.Process]::GetCurrentProcess()
	$logInfo = @"

******* Environment Information *******
ComputerName: $env:COMPUTERNAME
Username: $env:USERNAME
Domain: $env:USERDNSDOMAIN
PowerShell Version: $($PSVersionTable.PSVersion)
CLR Version: $($PSVersionTable.CLRVersion)
x64 OS: $([Environment]::Is64BitOperatingSystem)
x64 Process: $([Environment]::Is64BitProcess)
Windows Version: $(([Environment]::OSVersion).Version)
Process ID: $($processInformation.ID)
Process Path: $($processInformation.Path)
Process StartTime: $($processInformation.StartTime)
Process Arguments: $($processInformation.StartInfo.Arguments)
Process UserName: $($processInformation.StartInfo.UserName)
Process WorkingDirectory: $($processInformation.StartInfo.WorkingDirectory)
Process Environment Variables -
$($processInformation.StartInfo.EnvironmentVariables | Out-String)
***************************************

"@

	# Another way to get IIS information but may be unreliable: get-itemproperty HKLM:\SOFTWARE\Microsoft\InetStp\  | select setupstring,versionstring
	Write-LogMessage -Message $logInfo -NoTimestamp
}

function Get-SettingsObject
{
	[CmdletBinding()]
	Param
	(
		[string]
		$Config,

		[string]
		$ServiceModelXml
	)

	$settings = $null
	if($Config)
	{
		Write-LogMessage -Message 'Parsing config settings'
		$decodedConfig = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Config))
		$settings = ConvertFrom-Json $decodedConfig
		Write-LogMessage -Message 'Config settings parsed'
	}
	elseif ($ServiceModelXml)
	{
		Write-LogMessage -Message 'Parsing XML settings'
		$decodedXml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ServiceModelXml))
		$settings = [xml]$decodedXml;
		Write-LogMessage -Message 'XML settings parsed'
	}
	else
	{
		Write-LogMessage -Message 'No settings were found' -Warning
	}

	if ($settings)
	{
		$SkipMR = $false
		Update-ValueFromConfig -Settings $settings -PropertyName 'MR.Skip' -UpdateObject:([ref]$SkipMR) -UpdateObjectName 'SkipMR' -WarningCondition { $false } -IsBoolean
		if($SkipMR)
		{
			Write-LogMessage -Message 'Exiting MR deployment'
			exit
		}
	}

	return $settings
}

function Add-AssemblyResolver
{
	# Keeping empty method for backwards compatibility with older versions of non-slipstreamed callers
}

function Remove-AssemblyResolver
{
	# Keeping empty method for backwards compatibility with older versions of non-slipstreamed callers
}
function Get-DecryptedConnectionString
{
	[CmdletBinding()]
	[OutputType([string])]
	Param
	(
		[ValidateNotNull()]
		[pscustomobject]
		$InstallPaths,

		[ValidateNotNullOrEmpty()]
		[string]
		$ConnectionsConfigFilePath
	)

	[xml]$configContents = Get-Content $ConnectionsConfigFilePath -Raw

	$keyVaultPath = Join-Path -Path $InstallPaths.Services -ChildPath 'Microsoft.CE.VaultSDK.dll'
	if(Test-Path -Path $keyVaultPath)
	{
		Add-Type -Path $keyVaultPath
	}

	Add-Type -Path (Join-Path -Path $InstallPaths.Services -ChildPath 'Microsoft.Dynamics.Performance.Core.dll')
	if(([Microsoft.Dynamics.Performance.Core.SqlUtility]).GetMethod('DecryptConnectionString') -eq $null)
	{
		Add-Type -AssemblyName 'System.Security'
		$connectionStringBuilder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder -ArgumentList $configContents.connectionStrings.FirstChild.connectionString
		$decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String($connectionStringBuilder.Password), (New-Object 'System.Byte[]' -ArgumentList 0), [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
		[string]$decryptedPassword = [System.Text.Encoding]::ASCII.GetString($decryptedBytes)
		$connectionStringBuilder.Password = $decryptedPassword
		return $connectionStringBuilder.ConnectionString
	}
	else
	{
		return [Microsoft.Dynamics.Performance.Core.SqlUtility]::DecryptConnectionString($configContents.connectionStrings.FirstChild.connectionString)
	}
}

function Get-SettingsConfigValue
{
	[CmdletBinding()]
	[OutputType([string])]
	Param
	(
		[ValidateNotNull()]
		[xml]
		$SettingsXml,

		[ValidateNotNullOrEmpty()]
		[string]
		$SettingName
	)

	$node = $SettingsXml.appSettings.ChildNodes | where { $_.PSObject.Properties.name -match 'key' -and $_.key -like $SettingName } | Select-Object -First 1
	if ($node)
	{
		return $node.value
	}

	return $null
}

function Get-IsApplicationService
{
	[CmdletBinding()]
	[OutputType([boolean])]
	Param
	(
	)

	return (Test-Path -Path (Get-MRFilePaths).ApplicationServiceConnectionsConfig)
}

function Get-DeployedServiceModelName
{
	[CmdletBinding()]
	[OutputType([string])]
	Param
	(
	)

	$serviceModelName = $null
	$installPath = Get-MRFilePaths
	if (Get-IsApplicationService)
	{
		$deployedProcessService = Get-Service -Name "MR2012ProcessService" -ErrorAction SilentlyContinue
		if ($deployedProcessService)
		{
			$serviceModelName = 'MROneBox'
		}
		else
		{
			$serviceModelName = 'MRApplicationService'
		}
	}
	else
	{
		$serviceModelName = 'MRProcessService'
	}

	return $serviceModelName
}

function Reset-ReportDefinitionMaps
{
	# Resetting the FINANCIALREPORTS and FINANCIALREPORTVERSION maps to ensure current data in AXDB
	[CmdletBinding()]
	Param
	(
		# SQL server instance name.
		[Parameter(ValueFromPipelineByPropertyName = $true,Position = 0)]
		[string]
		[ValidateNotNullOrEmpty()]
		$ServerInstance,

		 # Database name.
		[Parameter(ValueFromPipelineByPropertyName = $true,Position = 1)]
		[string]
		[ValidateNotNullOrEmpty()]
		$DatabaseName,

		# SQL credential.
		[Parameter(ValueFromPipelineByPropertyName = $true,Position = 2)]
		[pscredential]
		$Credential,

		[ValidateNotNullOrEmpty()]
		[string]
		$DataEncryptionCertificateThumbprint,

		[string]
		$DataSigningCertificateThumbprint
	)

	try
	{
		if (!$DataSigningCertificateThumbprint)
		{
			$DataSigningCertificateThumbprint = $DataEncryptionCertificateThumbprint
		}

		$installPaths = Get-MRFilePaths
		#Check if the current machine is AOS
		if(Test-Path -Path $installPaths.ApplicationServiceSettingsConfig )
		{
			Write-LogMessage -Message "Resetting report definition and version maps."
			$mrConnectionString = Get-ConnectionString -Server $ServerInstance -Database $DatabaseName -Credential $Credential
			$axConnectionString = Get-AXConnectionString -MRConnectionString $mrConnectionString -DataEncryptionCertificateThumbprint $DataEncryptionCertificateThumbprint -DataSigningCertificateThumbprint $DataSigningCertificateThumbprint

			$truncateAxReportTables = @"
IF EXISTS (SELECT 1 FROM [INFORMATION_SCHEMA].[TABLES] WHERE [TABLE_SCHEMA] = 'dbo' and [TABLE_NAME] = 'FINANCIALREPORTS')
BEGIN
	TRUNCATE TABLE [dbo].[FINANCIALREPORTS]
END

IF EXISTS (SELECT 1 FROM [INFORMATION_SCHEMA].[TABLES] WHERE [TABLE_SCHEMA] = 'dbo' and [TABLE_NAME] = 'FINANCIALREPORTVERSION')
BEGIN
	TRUNCATE TABLE [dbo].[FINANCIALREPORTVERSION]
END
"@

			Invoke-SqlQuery -ConnectionString $axConnectionString -Query $truncateAxReportTables -ResultReader (Get-ExecuteNonQueryReader)
			Write-LogMessage -Message "Completed truncating FinancialReports and FinancialReportVersions Tables"

			$resetMapTokensQuery = @"
UPDATE [Connector].[Map]
SET [ReaderToken] = null
WHERE [MapId] IN 
(
	SELECT [Id] 
	FROM [Scheduling].[Task] 
	WHERE [Name] LIKE 'MR Report Definitions%' or [Name] LIKE 'MR Report Versions%'
)
"@
			Invoke-SqlQuery -ConnectionString $mrConnectionString -Query $resetMapTokensQuery -ResultReader (Get-ExecuteNonQueryReader)
			Write-LogMessage -Message "Completed resetting report definition and version maps"
		}
	}
	catch
	{
		Write-LogMessage -Message 'Error has encountered while resetting ReportDefinitionMaps.' -Error
		Write-ErrorDetail -ErrorThrown $_
		throw
	}
}

function Publish-AXDatabaseSettingsForUpdate
{
	[CmdletBinding()]
	Param
	(
		# Connection string to the AX database
		[string]
		[ValidateNotNullOrEmpty()]
		$AxAdminConnectionString
	)

	Write-MRInfoMessage 'Calling Publish-AXDatabaseSettingsForUpdate'

	Add-ReportingIntegrationSchema -AxAdminConnectionString $AxAdminConnectionString

	# Ensure ax runtime user has proper permissions if the user exists
	$runtimeUser = (Get-MRDefaultValues).AXSqlRuntimeUserName
	if ($runtimeUser)
	{
		Write-MRInfoMessage "Adding AX runtime user '$runtimeUser' to ReportingIntegrationUser role"
		$addUserToRoleQuery = @"
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '$runtimeUser')
BEGIN
	EXEC sp_addrolemember 'ReportingIntegrationUser', '$runtimeUser'
	EXEC sp_addrolemember 'db_datareader', '$runtimeUser'
	EXEC sp_addrolemember 'db_datawriter', '$runtimeUser'
END
"@
		Invoke-SqlQuery -ConnectionString $AxAdminConnectionString -Query $addUserToRoleQuery -ResultReader (Get-ExecuteNonQueryReader)
		Write-MRInfoMessage "Added AX runtime user '$runtimeUser' to ReportingIntegrationUser role"
	}

	Write-MRInfoMessage 'Completed calling Publish-AXDatabaseSettingsForUpdate'
}

function Add-ReportingIntegrationSchema
{
	[CmdletBinding()]
	Param
	(
		# Connection string to the AX database
		[string]
		[ValidateNotNullOrEmpty()]
		$AxAdminConnectionString
	)

	Write-MRInfoMessage 'Adding AX integration schema (Add-AXIntegrationSchema)'
	$addReportingIntegrationUserRole = @"
-----------------------------
PRINT 'Grant permissions to ReportingIntegrationUser role'
------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'ReportingIntegrationUser' and [type] = 'R')
BEGIN
	CREATE ROLE [ReportingIntegrationUser] AUTHORIZATION [dbo]
END

IF SCHEMA_ID('ReportingIntegration') IS NULL EXECUTE('CREATE SCHEMA [ReportingIntegration] AUTHORIZATION [dbo]')
GRANT CREATE TABLE TO [ReportingIntegrationUser]
GRANT CREATE VIEW TO [ReportingIntegrationUser]
GRANT ALTER        ON SCHEMA::[ReportingIntegration] TO [ReportingIntegrationUser]
GRANT DELETE       ON SCHEMA::[ReportingIntegration] TO [ReportingIntegrationUser]
GRANT INSERT       ON SCHEMA::[ReportingIntegration] TO [ReportingIntegrationUser]
GRANT SELECT       ON SCHEMA::[ReportingIntegration] TO [ReportingIntegrationUser]
GRANT UPDATE       ON SCHEMA::[ReportingIntegration] TO [ReportingIntegrationUser]
GRANT DELETE       ON SCHEMA::[dbo] TO [ReportingIntegrationUser]
GRANT INSERT       ON SCHEMA::[dbo] TO [ReportingIntegrationUser]
GRANT SELECT       ON SCHEMA::[dbo] TO [ReportingIntegrationUser]
GRANT UPDATE       ON SCHEMA::[dbo] TO [ReportingIntegrationUser]
GRANT ALTER        ON SCHEMA::[dbo] TO [ReportingIntegrationUser]
GRANT REFERENCES   ON SCHEMA::[dbo] TO [ReportingIntegrationUser]
GRANT VIEW CHANGE TRACKING ON SCHEMA::[dbo] TO [ReportingIntegrationUser]
"@

	Invoke-SqlQuery -ConnectionString $AxAdminConnectionString -Query $addReportingIntegrationUserRole -ResultReader (Get-ExecuteNonQueryReader)

	Write-MRInfoMessage 'Added AX integration schema'
}

function Update-UserRoles
{
	[CmdletBinding()]
	Param
	(
		# Connection string to the MR database
		[string]
		[ValidateNotNullOrEmpty()]
		$ConnectionString,

		[string]
		[ValidateNotNullOrEmpty()]
		$DataEncryptionCertificateThumbprint,

		[string]
		[ValidateNotNullOrEmpty()]
		$DataSigningCertificateThumbprint
	)

	Write-MRInfoMessage 'Updating user roles'

	# Re-create the mrruntimeuser if needed, re-assign permissions
    try
    {
	    Update-SqlUserPassword -AdminConnectionString $ConnectionString -Credential (New-Object System.Management.Automation.PSCredential((Get-MRDefaultValues).MRSqlRuntimeUserName, ((Get-MRDefaultValues).MRSqlRuntimeUserPassword | ConvertTo-SecureString -AsPlainText -Force)))
    }
    catch
    {
        Write-LogMessage -Message "Unable to insert/update mrruntime user account. Exception thrown $_" -Warning
    }
    	
    Update-MrRuntimeUserPermissions -AdminConnectionString $ConnectionString -RuntimeUserName (Get-MRDefaultValues).MRSqlRuntimeUserName

	# Re-create the axmrruntimeuser if needed, re-assign permissions
	$axAdminConnectionString = Get-AXConnectionString -MRConnectionString $ConnectionString -DataEncryptionCertificateThumbprint $DataEncryptionCertificateThumbprint -DataSigningCertificateThumbprint $DataSigningCertificateThumbprint
	$axRuntimeConnectionString = Get-AXConnectionString -MRConnectionString $ConnectionString -DataEncryptionCertificateThumbprint $DataEncryptionCertificateThumbprint -DataSigningCertificateThumbprint $DataSigningCertificateThumbprint -ConnectionType Runtime
	$axRuntimeConnectionStringBuilder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder -ArgumentList $axRuntimeConnectionString
    try
    {	
        Update-SqlUserPassword -AdminConnectionString $axAdminConnectionString -Credential (New-Object System.Management.Automation.PSCredential($axRuntimeConnectionStringBuilder.UserID, ($axRuntimeConnectionStringBuilder.Password | ConvertTo-SecureString -AsPlainText -Force)))
    }
    catch
    {
        Write-LogMessage -Message "Unable to insert/update axmrruntime user account. Exception thrown $_" -Warning
    }	

    Update-AxMrRuntimeUserPermissions -AdminConnectionString $axAdminConnectionString -RuntimeConnectionString $axRuntimeConnectionString

	Write-MRInfoMessage 'Completed update to user roles'
}

function Update-AxMrRuntimeUserPermissions
{
	[CmdletBinding()]
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$AdminConnectionString,

		[string]
		[ValidateNotNullOrEmpty()]
		$RuntimeConnectionString
	)

	Write-MRInfoMessage 'Updating AxMrRuntimeUser permissions'

	$axAdminConnectionStringBuilder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder -ArgumentList $AdminConnectionString
	$axRuntimeConnectionStringBuilder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder -ArgumentList $RuntimeConnectionString
	Set-MRDefaultValues -Settings @{'AXSqlRuntimeUserName'=$axRuntimeConnectionStringBuilder.UserID;'AXSqlUserName'=$axAdminConnectionStringBuilder.UserID;'AXSqlRuntimeUserPassword'=$axRuntimeConnectionStringBuilder.Password;'AXSqlUserPassword'=$axAdminConnectionStringBuilder.Password}

	Publish-AXDatabaseSettingsForUpdate -AxAdminConnectionString $AdminConnectionString

	Write-MRInfoMessage 'Completed updating AxMrRuntimeUser permissions'
}

<# .SYNOPSIS
	Update the SQL user with the appropriate password.
.DESCRIPTION
	Creates the contained database sql user if it doesn't exist, otherwise we
	just need to ensure the password for the user is correct.
.NOTES
	If the database doesn't support contained users, we do nothing.
#>
function Update-SqlUserPassword
{
	[CmdletBinding()]
	Param
	(
		# Connection string with permissions to create db users
		[string]
		[ValidateNotNullOrEmpty()]
		$AdminConnectionString,

		# Credential of the sql user to re-create
		[pscredential]
		[ValidateNotNullOrEmpty()]
		$Credential
	)

	$User = $Credential.UserName
	$Password = $Credential.GetNetworkCredential().Password

	Write-MRInfoMessage "Updating user $User account details."

	$query = @"
-- authentication_type 2 is Database authentication, so we can create the contained database user without needing login
IF EXISTS(SELECT 1 FROM sys.database_principals WHERE authentication_type = 2)
BEGIN
	PRINT 'Checking contained database users'
	IF NOT EXISTS(SELECT name FROM sys.database_principals WHERE name = '$User' AND TYPE = 'S')
	BEGIN
		PRINT 'Creating the contained user'
		CREATE USER [$User] WITH PASSWORD = N'$Password'
	END
	ELSE
	BEGIN
		PRINT 'Fixing the user password'
		ALTER USER [$User] WITH PASSWORD = N'$Password'
	END
END
"@
		Invoke-SqlQuery -ConnectionString $AdminConnectionString -Query $query -ResultReader (Get-ExecuteNonQueryReader)
		Write-MRInfoMessage "Completed updating user $User account details."
}

function Update-MrRuntimeUserPermissions
{
	[CmdletBinding()]
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$AdminConnectionString,

		[string]
		[ValidateNotNullOrEmpty()]
		$RuntimeUserName
	)

	Write-MRInfoMessage 'Updating MrRuntimeUser permissions'
	$query = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'GeneralUser' and [type] = 'R')
BEGIN
	CREATE ROLE [GeneralUser] AUTHORIZATION [dbo]
END

--Grant Permissions
GRANT CREATE TABLE TO [GeneralUser]
GRANT VIEW DEFINITION TO [GeneralUser]
GRANT VIEW DATABASE STATE TO [GeneralUser]

--Change schema ownership for MRDB schemas
IF EXISTS (SELECT * FROM sys.schemas WHERE name = 'Datamart')
BEGIN
	ALTER AUTHORIZATION ON SCHEMA::[Datamart] TO [GeneralUser] 
END
ALTER AUTHORIZATION ON SCHEMA::[Reporting] TO [GeneralUser] 
ALTER AUTHORIZATION ON SCHEMA::[Connector] TO [GeneralUser] 
ALTER AUTHORIZATION ON SCHEMA::[Scheduling] TO [GeneralUser]
"@
	Invoke-SqlQuery -ConnectionString $AdminConnectionString -Query $query -ResultReader (Get-ExecuteNonQueryReader)

	# Add runtime user to the GeneralUser role
	$addUserToRoleQuery = @"
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '$RuntimeUserName')
BEGIN
	EXEC sp_addrolemember 'GeneralUser', '$RuntimeUserName'
	EXEC sp_addrolemember 'db_datareader', '$RuntimeUserName'
	EXEC sp_addrolemember 'db_datawriter', '$RuntimeUserName'
END
"@

	Invoke-SqlQuery -ConnectionString $AdminConnectionString -Query $addUserToRoleQuery -ResultReader (Get-ExecuteNonQueryReader)

	Write-MRInfoMessage 'Completed updating MrRuntimeUser permissions'
}

function Get-DataSigningCertificateThumbprint
{
	[CmdletBinding()]
	Param
	(
		[xml]
		[ValidateNotNull()]
		$SettingsXml,

		[string]
		[ValidateNotNullOrEmpty()]
		$DataEncryptionCertificateThumbprint
	)

	$signingCertificateThumbprint = Get-SettingsConfigValue -SettingsXml $SettingsXml -SettingName 'DataSigningCertificateThumbprint'
	if (!$signingCertificateThumbprint)
	{
		$signingCertificateThumbprint = $DataEncryptionCertificateThumbprint
	}

	return $signingCertificateThumbprint
}

<#
    Get installed MR version
#>
function Get-BinaryVersion
{
	[CmdletBinding()]
	[OutputType([version])]
	Param()

	$dllNamePattern = 'Microsoft.Dynamics.Performance.Reporting.*.dll'
	$dll = Get-ChildItem -Path (Get-MRFilePaths).Services | Where-Object -Property Name -ILike $dllNamePattern | Select-Object -First 1
	return [version]$dll.VersionInfo.FileVersion
}

function Get-PackageVersion
{
	[CmdletBinding()]
	[OutputType([version])]
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$CabFilePath
	)

	[version]$version = $null
	$tempDir = "$script:currentFolder\cab_temp"
	$dllNamePattern = 'Microsoft.Dynamics.Performance.Reporting.*.dll'
	if (Test-Path -Path $tempDir)
	{
		Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
	}
	
	[void](New-Item -Path $tempDir -ItemType Directory -Force)
	[string]$packageDll = ''
	try
	{
		$shell = New-Object -ComObject 'Shell.Application'
		$cabPath = Resolve-Path -Path (Join-Path -Path $CabFilePath -ChildPath 'MRServer.cab')
		$dllReference = $shell.NameSpace($cabPath.ToString()).Items() | Where-Object -Property Name -ILike $dllNamePattern | Select-Object -First 1
		[void]($shell.NameSpace($tempDir).CopyHere($dllReference))
		$packageDll = Join-Path -Path $tempDir -ChildPath $dllReference.Name
		$packageDll = Resolve-Path -Path $packageDll
		$version = [version](Get-Item -Path $packageDll).VersionInfo.FileVersion
	}
	finally
	{	
		Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
	}

	return $version
}

<#
    Get MR database version
#>
function Get-DatabaseVersion
{
	[CmdletBinding()]
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$ConnectionString
	)

    $getVersionQuery = "SELECT VALUE FROM [Reporting].[ControlProperties] WHERE Name = 'SchemaVersion'"
	$sqlResult = Invoke-SqlQuery -ConnectionString $ConnectionString -Query $getVersionQuery -ResultReader (Get-ExecuteScalarReader)
	return [version]$sqlResult
}

function Get-UpdateAdapterQuery
{
	[CmdletBinding()]
	[OutputType([string])]
	Param
	(
		# Id for the adapter to update
		[string]
		[ValidateNotNullOrEmpty()]
		$AdapterId,

		# Name of the field to update
		[string]
		[ValidateNotNullOrEmpty()]
		$FieldName,

		# New value for the field
		[string]
		[ValidateNotNullOrEmpty()]
		$Value
	)

	return @"
Update [Connector].[MapCategoryAdapterSettings] SET 
Settings.modify('replace value of (/*:SettingsCollection/*:ArrayOfSettingsValue/*:SettingsValue[*:FieldDefinition/@Name=("$FieldName")]/*:Value/text())[1] with ("$Value")')
where AdapterId = '$AdapterId'

"@
}

function Write-ConfigSetting
{
	[CmdletBinding()]
	Param
	(
		[xml]
		[ValidateNotNull()]
		$SettingsXml,

		[string]
		[ValidateNotNullOrEmpty()]
		$SettingKey,

		[string]
		[ValidateNotNullOrEmpty()]
		$SettingValue
	)

	Write-LogMessage -Message "Adding or updating config setting with key '$SettingKey', value '$SettingValue'"
	$node = $SettingsXml.SelectSingleNode('//appSettings').ChildNodes | where { $_.PSObject.Properties.name -match 'key' -and $_.key -like $SettingKey } | Select-Object -First 1
	if ($node)
	{
		$node.value = $SettingValue
	}
	else
	{
		$node = $SettingsXml.CreateElement('add')
		$node.SetAttribute('key', $SettingKey)
		$node.SetAttribute('value', $SettingValue)
		[void]($SettingsXml.SelectSingleNode('//appSettings').AppendChild($node))
	}
}

<#
	.Synopsis
	Executes the given logic in a retry loop
#>
function Invoke-RetryLoop
{
	[CmdletBinding()]
	Param
	(
		# How many times to retry
		[int]
		[ValidateNotNull()]
		$RetryCount,

		# How long in seconds to delay between retries
		[int]
		[ValidateNotNull()]
		$DelayInSeconds,

		# Action to retry. Should return a boolean indicating if the action was
		# successful (and therefore no more retries are required).
		[scriptblock]
		[ValidateNotNull()]
		$Action
	)

	[bool]$success = $false
	while ($RetryCount -gt 0 -and !$success)
	{
		Write-LogMessage -Message "Executing retry loop. Retry count is $RetryCount"
		$success = Invoke-Command -ScriptBlock $Action
		if (!$success)
		{
			$RetryCount -= 1
			Start-Sleep -Seconds $DelayInSeconds
		}
	}

	return $success
}
# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDIE/eRK0UUzL7p
# rmMvpXW1/XZ4fLwYrGUj/opbSrRgwaCCDYEwggX/MIID56ADAgECAhMzAAACUosz
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgb3u129yd
# 9qbN/8NgmzlhUw/oo21YA5Ix8I9M3Ab9du4wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCFsXsYiLjlreLof7O3rHQHv4gDopSUol2OMFXAAae7
# jrOMJUpS9HHAaqrlu2mW0wKGgXO4l/fWua9ygbZRpio4l/ze4afSoPPqvxZWZywf
# osmBP2FKbvKjbNojUR9rMNIFBVn6wrNMqMJCL1b130sIyHAaVsqyL8JfMpxUHuz+
# rORIOPRWJ8HO+6vJ8FOwxcfduKQ1rxPyLXIzvI8s6yTwgP1Q/XH0u7JvOcEnd3i6
# ODAldGyyp+HjFSJznDZvRSSzjPksNT7nOig2gmXi865OUXXT+SHx6T/9dGrR3aL3
# oqiLGbyCpMTvDR0xvjaUw3E719HzizsA2708aq6fcgJYoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIEfxUho0gvVKi5w+5XYhJcLeGV9Y4CMmscLCHAAu
# VuYzAgZhktY1BOoYEzIwMjExMjAxMDgzODAwLjY5NVowBIACAfSggdCkgc0wgcox
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
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgz0gl5bo9
# Y9OekRZUA78iMwYWW2E85BP23U6b/cw3KFQwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCBr9u6EInnsZYEts/Fj/rIFv0YZW1ynhXKOP2hVPUU5IzCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABS0+ypkjV5MJRAAAA
# AAFLMCIEIPn8WBJ+AznSo18LyJTB8Xas1FwSkCpEYUBMCoNgn10pMA0GCSqGSIb3
# DQEBCwUABIIBAIqxV/s2j8olJIzSEDulB7UKbCf78nZA3QRRcrKazdH6eQaFzEfu
# 3E3ekVkORoziW7gTQB/KxgbXcHram9nJMr7sUcIW8P/9MlpLAKFOSdjcax7MoaKt
# WzRZ6iJptWsaWKwOeVVxJgzCExsUkj/amxctM9U0PZVmP83dESsXYC6icWscWkdi
# DiQbJ+YvU2+xOKprSqlIINpHjAoIvGTk0dv87vfhoXD+xJuZE3uDN4jHNr3WR8pq
# UPLZjCHzkPxW/hF/lucXvCnYLpPIWBRpc17YXksC4RGp7qfoVoqPRoUmAASCigP3
# gvYKodqgiTi83OdE92H2KXybqb5L5HYmc7Q=
# SIG # End signature block
