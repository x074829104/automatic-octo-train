<#
.Synopsis
   Entry point for calling into MRDeployment module for executing any Management Reporter deployment activities
.DESCRIPTION
   Besides being a single entry point it also provides logging, debugging, and profiling functionality.
#>
[CmdletBinding()]
Param
(
	# Provides a log name to use as the log file name (no extension)
	[string]
	$LogFileName,

	# Uses credential for SQL authentication for communicating to your local default SQL server instance. If not specific, Windows authentication is used.
	[pscredential]
	$SqlCredential,

	# Indicates to remove a deployment of MR
	[switch]
	$Remove,

	# Indicates the script will be measured, useful for profiling
	[switch]
	$Measure,

	# On fileshare script's location is used, on OneBox $env:dplLogDir is used.
	[string]
	$LogPath = "$PSScriptRoot",

	# Path to directory containing MSI and CAB file for MR server. Supports shortcut (.lnk) files. This path is used if the MSI is not next to this script file.
	[string]
	$MsiPath = '\\cpmint-file01\builds\mr\AX7_Build.lnk',

	# Indicates to force the -MsiPath to be used if the MSI is next to the script file.
	[switch]
	$ForceMsiPath,

	# Indicates to force a non-recursive search for the MSI file.
	[switch]
	$ForceNonRecursiveFind,

	# Indicates to suppresses any warnings that would show from -Remove.
	[switch]
	$SuppressWarning,

	# Data to deploy. 'None' if no DDM data is to be deployed. 'Contoso' or 'Demo' if a DDM backup is being used. 'Integrate' to setup a DDM integration.
	[string]
	$DDMData = 'None',

	# Deploys Process Service Only. Requires a MR database to already exist.
	[switch]
	$ApplicationOnly,

	# Deploys only Application components (WCF services, web service, click-once).
	[switch]
	$ProcessServiceOnly,

	# Parameters supplied to New-MRSetup. Note some parameters get overridden during script execution such as DeployDDMDataBackup, PathToDDMData, IntegrateDDM, ApplicationOnly, and ProcessServiceOnly.
	[Hashtable]
	[ValidateNotNull()]
	$NewMRSetupParameters = @{DeployToIIS = $true; DeployClickOnceDesignerToIIS = $true},

	# Parameters supplied to Remove-MRSetup. Note some parameters get overridden during script executing such as ProcessServiceOnly.
	[Hashtable]
	[ValidateNotNull()]
	$RemoveMRSetupParameters = @{RemoveFromIIS = $true; RemoveClickOnceDesignerFromIIS = $true; RemoveDDMData = $true},

	# Values used to override MR's default parameters.
	[Hashtable]
	$MRDefaultValues,

	# Indicates to not install or remove MSI.
	[switch]
	$NoInstall,

	# Indicates to not remove any MR components if they already exist. Should only be used on fresh environments.
	[switch]
	$NoRemoval,

	# Log file set from Deployment task.
	[string]
	$log,

	# JSON encoded dictionary containing configuration settings from Deployment task.
	[string]
	$config,

	# Path to install MSI to, this overrides the default settings of the MSI. Default is c:\FinancialReporting.
	[string]
	$InstallLocation = 'c:\FinancialReporting',

	# Indicates to not deploy monitoring.
	[switch]
	$NoMonitoring,

	# Path to monitoring directory containing ETW manifests and resource DLLs. Specifying this make the files be copied but the monitoring agent won't be started.
	[string]
	$MonitoringPath,

	# Number of seconds to wait for long sql commands
	[long]
	$SqlTimeoutSeconds,

	# Indicates to show function calls in log
	[switch]
	$ShowFunctionCalls,

	# Indicates to not isolate calls in AppDomains.
	[switch]
	$NoAppDomain,

	# Force AOS URI and Application Service URI to use LocalHost regardless of what is passed in
	[switch]
	$ForceLocalHost,

	# Indicates to enforce SQL encryption and SSL certificate is valid.
	[switch]
	$EnforceEncryption,

	# Includes an extra list of variables to exclude from AppDomain
	[string[]]
	$VariableExcludeList = @(),

	# Used by DSC, actual XML file in base64 form. Use if cert data/info is needed.
	[string]
	$serviceModelXml
)

. "$PSScriptRoot\ScriptSetup.ps1"
Set-LogPath -FullLogPath $log -LogDir $LogPath -LogFileName $LogFileName
if ($log -and !$LogPath)
{
	$LogPath = [System.IO.Path]::GetDirectoryName($log)
}

Write-EnvironmentDataToLog
$Settings = Get-SettingsObject -Config $config -ServiceModelXml $serviceModelXml
$StartTime = Get-Date

#region Script Setup
# Constants
Set-Variable -Name ModuleName -Value 'MRDeploy' -Option Constant
Set-Variable -Name PsAppDomainCmdlet -Value 'Microsoft.Dynamics.Performance.Deployment.Commands.InvokePSAppDomain' -Option Constant

# Prevent bleed over of module from a previous session
if(Get-Module $ModuleName)
{
	Remove-Module $ModuleName -Force
}
#endregion

#region Private Script Functions
function ConvertTo-LocalHost
{
	param
	(
		[ValidateNotNull()]
		[uri]
		$OriginalUri       
	)

	$uriBuilder = New-Object 'System.UriBuilder' -ArgumentList ($OriginalUri)
	$uriBuilder.Host = 'localhost';

	return $uriBuilder.ToString()
}
#endregion

#region Logging
[string]$mrDeploymentLogsFolder = $null
if($LogPath)
{
	$mrDeploymentLogsFolder = Join-Path -Path $LogPath -ChildPath MRDeploymentLogs
	[void](New-Item -Path $mrDeploymentLogsFolder -ItemType Directory -Force -ErrorAction SilentlyContinue)
}

if($Remove)
{
	Write-LogMessage "MR Removal requested at $(Get-Date -Format 'G')" -NoTimestamp
}
else
{
	Write-LogMessage "MR Deployment requested at $(Get-Date -Format 'G')" -NoTimestamp
}
#endregion

#region Convert Config Settings
if($Settings)
{
	# Some of these settings get applied here, some get applied to MRDefaultValues
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.NoMonitoring' -UpdateObject:([ref]$NoMonitoring) -UpdateObjectName 'NoMonitoring' -IsBoolean
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.NoRemoval' -UpdateObject:([ref]$NoRemoval) -UpdateObjectName 'NoRemoval' -IsBoolean
	# TODO remove property below once functions are seperated from script, dpl script won't support this
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.ProcessServiceOnly' -UpdateObject:([ref]$ProcessServiceOnly) -UpdateObjectName 'ProcessServiceOnly' -IsBoolean -WarningCondition { $false }
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.ApplicationOnly' -UpdateObject:([ref]$ApplicationOnly) -UpdateObjectName 'ApplicationOnly' -IsBoolean -WarningCondition { $false }
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDMData' -UpdateObject:([ref]$DDMData) -UpdateObjectName 'DDMData' -WarningCondition { !$ProcessServiceOnly }
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.ForceLocalHost' -UpdateObject:([ref]$ForceLocalHost) -UpdateObjectName 'ForceLocalHost' -IsBoolean
	# TODO remove property below once functions are seperated from script, dpl script won't support this
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.EnforceEncryption' -UpdateObject:([ref]$EnforceEncryption) -UpdateObjectName 'EnforceEncryption' -IsBoolean -WarningCondition { !$ProcessServiceOnly }
}
# Generate a random value to be used through each script execution of this script instance
# Allows for a static generated value between things like setup and instrumentation
$generatedValue = [string]([Guid]::NewGuid())
#endregion

#region Removal handling
if($NoRemoval)
{
	# Indicates it is multi-box, no need to use AppDomains
	Write-LogMessage -Message 'Setting -NoAppDomain because of -NoRemoval'
	$NoAppDomain = $true
}

if($Remove)
{
	# Remove overrides NoRemoval
	Write-LogMessage -Message 'Setting -NoRemoval to false because the -Remove flag was passed'
	$NoRemoval = $false
}
#endregion

#region Verify PsAppDomain Cmdlet exists and import it
function Find-PsAppDomainCmdlet
{
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$Path = "$env:TEMP\$PsAppDomainCmdlet.dll",
		
		[string]
		[ValidateNotNullOrEmpty()]
		$OriginalPath = "$PSScriptRoot\$PsAppDomainCmdlet.dll",

		[switch]
		$Copy,

		[switch]
		$Remove,

		[switch]
		$Verify,

		[switch]
		$Import
	)

	if($Verify)
	{
		Write-LogMessage -Message "Verifying '$OriginalPath' exists"
		if(!(Test-Path $OriginalPath))
		{
			# Using Write-Error to ensure it reaches log, throwing after as a safety precaution
			Write-Error "Failed to find $OriginalPath" *>&1 | Out-Log
			throw 'PsAppDomainCmdlet is missing'
		}
	}

	if($Remove)
	{
		if(Get-Module $PsAppDomainCmdlet)
		{
			Write-LogMessage -Message "Removing module '$PsAppDomainCmdlet'"
			Remove-Module $PsAppDomainCmdlet -Force
		}
	}

	if($Copy)
	{
		# Bug 3620448 - Microsoft.Dynamics.Performance.Deployment.Commands.InvokePSAppDomain.dll causing deployment cleanup to fail
		try
		{
			Copy-Item -Path $OriginalPath -Destination $Path -Force
		}
		catch
		{
			# Ignore if it can't replace
			Write-LogMessage -Message "Unable to update $Path" -Warning
		}
	}

	if($Import)
	{
		Write-LogMessage -Message "Importing $Path"
		Import-Module $Path
	}
}

if(!$NoAppDomain)
{
	Find-PsAppDomainCmdlet -Verify -Copy -Remove -Import
}
#endregion

#region Populate Variables
function Get-PSVariables
{
	[CmdletBinding()]
	[OutputType([hashtable])]
	Param
	(
	)

	# Do not include ? in exclude list because that is a wildcard and will exclude one character variables
	$excludeList = @('$', '^', 'args', '_', 'null', 'psitem', 'true', `
		'false', 'host', 'Error', 'ErrorView', 'ExecutionContext', 'FormatEnumerationLimit', 'input', `
		'LASTEXITCODE', 'StackTrace', 'MyInvocation', 'NestedPromptLevel', 'ShellId', 'PWD', 'psISE', `
		'PSHOME', 'PSEmailServer', 'PSDefaultParameterValues', 'PSCulture', 'PSCommandPath', `
		'PSBoundParameters', 'OutputEncoding', 'profile', 'PSScriptRoot', 'PSSessionApplicationName', `
		'PSSessionConfigurationName', 'PSSessionOption', 'PSUICulture', 'psAppDomainCmdletPath', `
		'psUnsupportedConsoleApplications', 'PSVersionTable', 'MaximumAliasCount', 'PSCmdlet', `
		'MaximumDriveCount', 'MaximumErrorCount', 'MaximumFunctionCount', 'MaximumHistoryCount', `
		'MaximumVariableCount', 'PID', 'HOME', 'ConsoleFileName', 'excludeList', 'executingDirectory', `
		'VariableExcludeList', 'Measure', 'config', 'log', 'NoAppDomain', `
		'InstallLocation', 'MsiPath', 'ForceMsiPath', 'ForceNonRecursiveFind', 'NoInstall', 'PsAppDomainCmdlet', `
		'variables', 'processInformation', 'CurrentlyExecutingCommand', 'logInfo', 'processInformation')

	$excludeList += $VariableExcludeList

	$variables = Get-Variable -Scope 1 -Exclude $excludeList | Where-Object Name -ne '?'

	# Convert to hashtable
	$variablesHashTable = @{}
	foreach($variable in $variables)
	{
		if(!$variable.Name)
		{
			continue
		}

		if($variable.Value -ne $null)
		{
			# some variable types are not serializable, they need to be converted
			if($variable.Value -is [System.Management.Automation.SwitchParameter])
			{
				$variablesHashTable.Add($variable.Name, ([bool]($variable.Value)))
				continue
			}
		}

		$variablesHashTable.Add($variable.Name, $variable.Value)
	}

	Write-Debug ($variablesHashTable | Out-String)

	return $variablesHashTable
}

# Gets overriden in AppDomains
$dplScriptRoot = $PSScriptRoot

# Calling this early to reduce the number of variables to exclude
if(!$NoAppDomain)
{
	$variables = Get-PSVariables
}
#endregion

#region ScriptExecution object
function New-ExecutionGroup
{
	[CmdletBinding()]
	Param
	(
		[string]
		[ValidateNotNullOrEmpty()]
		$Name
	)

	$group = New-Module -ScriptBlock {
		[string]$Name = ''
		[PSCustomObject]$ExecuteOnCondition = [PSCustomObject]@{}
		[PSCustomObject[]]$ScriptExecutions = @()

		Export-ModuleMember -Function * -Variable *
	} -AsCustomObject

	$group.Name = $Name

	return $group
}
#endregion

#region Populate Commands
<#
Implementation Notes:
* Functions are only needed if -UseAppDomain is specified
* Name is always required
* You must include functions called within specified functions (if they are invoked in the path of execution, ex: Out-Log does not need to be included)
* You do not need to include any MRDeploy functions
* ExecuteOnCondition is a ScriptExecution and can't use switch -UseAppDomain
* ExecuteOnCondition should return a boolean and will be called by Invoke-ExecutionScript -ReturnLastOutput
* For executions that specify -UseAppDomain [switch] are casted to bool (use [bool]$SwitchName to ensure it always works)
* Don't use $PSScriptRoot in executions that have -UseAppDomain, use $dplScriptRoot
#>
$newMRSetupExecution = New-ScriptExecution -Name 'New MR Setup' -UseAppDomain `
	-ErrorCode $ErrorCodes.NewMRSetup `
	-Functions @('Write-LogMessage', 'Remove-InvalidParameters') `
	-Script {
		$restoredDDM = $DDMData -ilike '*restored*'

		$NewMRSetupParameters.DeployDDMDataBackup = $false
		$NewMRSetupParameters.PathToDDMData = ''
		$NewMRSetupParameters.ProcessServiceOnly = [bool]$ProcessServiceOnly
		$NewMRSetupParameters.ApplicationOnly = [bool]$ApplicationOnly
		$NewMRSetupParameters.IntegrateDDM = $true
		$NewMRSetupParameters.NoRemoval = [bool]$NoRemoval
		$NewMRSetupParameters.CheckDDMEmpty = $restoredDDM
		$NewMRSetupParameters.ConsolidateAX = $false
	
		# Remove any parameters that may not exist (likely only going to filter ones specified to the script)
		$NewMRSetupParameters = Remove-InvalidParameters -Command New-MRSetup -Parameters $NewMRSetupParameters -ModuleName $ModuleName

		# From MRDeploy module (splatting parameters)
		New-MRSetup @NewMRSetupParameters
	}
	
$removeMRIfNeededExecution = New-ScriptExecution -Name 'Remove MR Install If Needed' `
	-ErrorCode $ErrorCodes.UninstallManagementReporter `
	-Script {
		Uninstall-MRServer -SuppressWarning -WarningMessageBeforeUninstall 'MR install left behind from a previous deployment detected, removal process could be incomplete causing next deployment to fail'
	}

$removeMRSetupExecution = New-ScriptExecution -Name 'Remove MR Setup' -UseAppDomain `
	-ErrorCode $ErrorCodes.RemoveMRSetup `
	-Functions @('Write-LogMessage', 'Remove-InvalidParameters') `
	-Script {
		# Update parameters
		$RemoveMRSetupParameters.ProcessServiceOnly = [bool]$ProcessServiceOnly

		# Remove any parameters that may not exist (could remove ones specified or new ones added that don't exist in older versions that are being removed)
		$RemoveMRSetupParameters = Remove-InvalidParameters -Command Remove-MRSetup -Parameters $RemoveMRSetupParameters -ModuleName $ModuleName

		# From MRDeploy module (splatting parameters)
		Remove-MRSetup @RemoveMRSetupParameters
	}

$setMRDefaultValuesExecution = New-ScriptExecution -Name 'Update MR Default Values' -UseAppDomain `
	-ErrorCode $ErrorCodes.UpdateDefaultValues `
	-Functions @('Write-LogMessage', 'Test-PropertyExists', 'Remove-InvalidParameters', 'Update-ValueFromConfig', 'Test-CommandExists', 'ConvertTo-LocalHost') `
	-Script {
		# TODO this area can be cleaned up after a few iterations (ensures everyone is on a newer version)
	
		if(!$MRDefaultValues)
		{
			# Initialize
			[hashtable]$MRDefaultValues = @{}
		}

		# Convert $Settings to MRDefaultValues
		if($Settings)
		{
			# For settings on MR database write warnings if the settings are not specified
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DataAccess.Database' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'MRDatabaseName'
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DataAccess.DbServer' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'MRSqlServerName'
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DataAccess.SqlUser' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'MRSqlUserName'
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DataAccess.SqlPwd' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'MRSqlUserPassword' -HideValue -ResolveSecret:$Remove

			# DDM database settings, only warn if ProcessServiceOnly wasn't specified
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.Database' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'DDMDatabaseName' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.DbServer' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'DDMSqlServerName' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.SqlUser' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'DDMSqlUserName' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.SqlPwd' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'DDMSqlUserPassword' -WarningCondition { !$ProcessServiceOnly } -HideValue -ResolveSecret:$Remove
		
			# AX database settings, only warn if ProcessServiceOnly wasn't specified
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.Database' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXDatabaseName' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.DbServer' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AosSqlServerName' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.SqlUser' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXSqlUserName' -WarningCondition { !$ProcessServiceOnly } 
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.SqlPwd' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXSqlUserPassword' -WarningCondition { !$ProcessServiceOnly } -HideValue -ResolveSecret:$Remove
											  
			# Environment Settings			  
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.CsuClientCertThumbprint' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXCertThumbprint' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AXSslCertThumbprint' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXSslCertThumbprint' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DataEncryptionCertThumbprint' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'DataEncryptionCertThumbprint' -WarningCondition { $true }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DataSigningCertThumbprint' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'DataSigningCertThumbprint' -WarningCondition { $true }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.Realm' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXFederationRealm' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AcsTokenIssuer' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXTokenIssuer' -WarningCondition { !$ProcessServiceOnly }
											  
			# AAD metadata endoint settings	  
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AADMetadataLocationFormat' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXAADMetadataLocationFormat' -WarningCondition { !$ProcessServiceOnly }
			Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AADTenantId' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AXAADTenantId' -WarningCondition { !$ProcessServiceOnly }

			if(!$ProcessServiceOnly)
			{
				Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AOSWebSiteName' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AosWebsiteName' -Mandatory
				Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.ServicesUrl' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'MRNonSoapApplicationServerName' -Mandatory
				Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.SoapServicesUrl' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'MRApplicationServerName' -Mandatory
				Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.SoapServicesUrl' -MRDefaultValues:([ref]$MRDefaultValues) -MRDefaultValueName 'AosServerName' -Mandatory
			}
		}

		if($ForceLocalHost)
		{
			if($MRDefaultValues.ContainsKey('AosServerName'))
			{
				 $MRDefaultValues.AosServerName = ConvertTo-LocalHost $MRDefaultValues.AosServerName
			}
			else
			{
				$MRDefaultValues.AosServerName = ConvertTo-LocalHost (Get-MRDefaultValues).AosServerName
			}

			if($MRDefaultValues.ContainsKey('MRApplicationServerName'))
			{
				 $MRDefaultValues.MRApplicationServerName = ConvertTo-LocalHost $MRDefaultValues.MRApplicationServerName
			}
			else
			{
				$MRDefaultValues.MRApplicationServerName = ConvertTo-LocalHost (Get-MRDefaultValues).MRApplicationServerName
			}
		}

		if($EnforceEncryption)
		{
			Write-LogMessage -Message 'Enforcing encryption'
			$MRDefaultValues.MRSqlEncryptConnection = $true
			$MRDefaultValues.MRSqlTrustServerCertConnection = 'False'
			$MRDefaultValues.AXSqlEncryptConnection = $true
			$MRDefaultValues.AXSqlTrustServerCertConnection = 'False'
		}

		$MRDefaultValues.AXCertUserName = (Get-MRDefaultValues).AXCertUserName
		$MRDefaultValues.AXSTSProviderName = (Get-MRDefaultValues).AXSTSProviderName

		Write-LogMessage -Message 'Discovering available MRDefaultValue commands'
		$testSetMRDefaultValuesCommand = Test-CommandExists -CommandName 'Set-MRDefaultValues'
		$testMRDefaultValueNameExistsCommand = Test-CommandExists -CommandName 'Test-MRDefaultValueNameExists'
		$testAssertMRDefaultValuesCommand = Test-CommandExists -CommandName 'Assert-MRDefaultValues'

		if($MRDefaultValues.Count -gt 0 -and $testSetMRDefaultValuesCommand)
		{
			Write-LogMessage -Message 'Updating MR default values with ones supplied by -MRDefaultValues'
			$defaultValueSettings = @{'Settings'=$MRDefaultValues;'WarnInsteadOfError'=$true}
			$defaultValueSettings = Remove-InvalidParameters -Command 'Set-MRDefaultValues' -Parameters $defaultValueSettings -ModuleName $ModuleName

			Set-MRDefaultValues @defaultValueSettings
			Write-LogMessage -Message 'MRDefaultValues have been set'   
		}
	
		if($LogPath -and $testSetMRDefaultValuesCommand -and $testMRDefaultValueNameExistsCommand)
		{
			if(Test-MRDefaultValueNameExists 'LogDirectory')
			{
				Write-LogMessage -Message 'Updating MR default log directory'
				Set-MRDefaultValues -SettingName 'LogDirectory' -SettingValue $LogPath
			}
			else
			{
				Write-LogMessage -Message 'Unable to set LogDirectory because a setting does not exist with that name' -Warning
			}
		}

		# dpl script deployments may not have SQL auth setup, we need to patch by creating sql auth credentials
		if(-not $SqlCredential -and -not (Get-MRDefaultValues).MRSqlUserPassword)
		{
			$dplUser = "MRdplSqlUser"
			Write-LogMessage -Message "Detected windows auth for SQL credentials, creating SQL user $dplUser for deployment compatibility."
			$secpasswd = ConvertTo-SecureString ($generatedValue) -AsPlainText -Force
			$SqlCredential = New-Object System.Management.Automation.PSCredential ($dplUser, $secpasswd)
			$userName = $SqlCredential.UserName
			$password = $SqlCredential.GetNetworkCredential().Password

			# Create the login and assign to sysadmin
			# Implementation note, sql query cannot contain GO statements
		$createSqlLoginIfNeeded = @"
IF NOT EXISTS(SELECT logins.name FROM sys.syslogins AS logins WHERE logins.name = N'$userName')
BEGIN
	CREATE LOGIN [$userName]
	WITH PASSWORD = N'$password',
	CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF
END
ELSE
BEGIN
	ALTER LOGIN $userName WITH PASSWORD = N'$password'
END
"@

			$connection = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
			$connection['Data Source'] = '.'
			$connection['Integrated Security'] = $true
			$connection['Password'] = 'fakepassword' # workaround Invoke-SqlQuery requires password
			$connectionString = $connection.ConnectionString

			Write-LogMessage -Message "Create login and set new password if needed"
			Invoke-SqlQuery -ConnectionString $connectionString -Query $createSqlLoginIfNeeded -ResultReader (Get-ExecuteNonQueryReader)
			Write-LogMessage -Message "Assign login to role"
			Invoke-SqlQuery -ConnectionString $connectionString -Query "EXEC sp_addsrvrolemember N'$userName', 'sysadmin'" -ResultReader (Get-ExecuteNonQueryReader)
		}

		if($SqlCredential -and $testSetMRDefaultValuesCommand -and $testMRDefaultValueNameExistsCommand)
		{
			$results = @('AXSqlUserName', 'AXSqlUserPassword', 'MRSqlUserName', 'MRSqlUserPassword') | Test-MRDefaultValueNameExists
			if($results)
			{
				Write-LogMessage -Message 'Updating default SQL auth credentials'
				$userName = $SqlCredential.UserName
				$password = $SqlCredential.GetNetworkCredential().Password
				Set-MRDefaultValues -Settings @{'AXSqlUserName'=$userName;'AXSqlUserPassword'=$password;'MRSqlUserName'=$userName;'MRSqlUserPassword'=$password}
			}
			else
			{
				Write-LogMessage -Message 'MR default values are not available for setting SQL auth' -Warning
			}

			$results = @('DDMSqlUserName', 'DDMSqlUserPassword') | Test-MRDefaultValueNameExists
			if($results)
			{
				Write-LogMessage -Message 'Updating default SQL auth credentials for DDM'
				$userName = $SqlCredential.UserName
				$password = $SqlCredential.GetNetworkCredential().Password
				Set-MRDefaultValues -Settings @{'DDMSqlUserName'=$userName;'DDMSqlUserPassword'=$password}
			}
		}

		if($MonitoringPath -and $testSetMRDefaultValuesCommand -and $testMRDefaultValueNameExistsCommand)
		{
			$results = @('MonitoringFolderPath', 'RestartMonitoringAgent') | Test-MRDefaultValueNameExists
			if($results)
			{
				Write-LogMessage -Message 'Updating monitoring path and disabling restarting monitoring agent'
				Set-MRDefaultValues -Settings @{'MonitoringFolderPath'=$MonitoringPath;'RestartMonitoringAgent'=$false}
			}
			else
			{
				Write-LogMessage -Message 'MR default values are not available for updating montoring path' -Warning
			}   
		}

		if($SqlTimeoutSeconds -and $testSetMRDefaultValuesCommand -and $testMRDefaultValueNameExistsCommand)
		{
			$results = @('SqlTimeoutSeconds') | Test-MRDefaultValueNameExists
			if($results)
			{
				Write-LogMessage -Message 'Updating default SQL timeout'
				Set-MRDefaultValues -Settings @{'SqlTimeoutSeconds'=$SqlTimeoutSeconds}
			}
			else
			{
				Write-LogMessage -Message 'MR default values are not available for sql timeout' -Warning
			}
		}

		if($ShowFunctionCalls -and $testSetMRDefaultValuesCommand -and $testMRDefaultValueNameExistsCommand)
		{
			if(Test-MRDefaultValueNameExists 'ShowFunctionCalls')
			{
				Write-LogMessage -Message 'Updating default value for showing function calls'
				Set-MRDefaultValues -SettingName 'ShowFunctionCalls' -SettingValue $true
			}
			else
			{
				Write-LogMessage -Message 'MR default values are not available for updating show function calls' -Warning
			}
		}

		# Ensure this is the last command executed in this function
		if($testAssertMRDefaultValuesCommand)
		{
			Write-LogMessage -Message 'Asserting MR default values'
			Assert-MRDefaultValues
		}
	}

$newMRInstrumentationDeploymentExecution = New-ScriptExecution -Name 'New MR Instrumentation' `
	-ErrorCode $ErrorCodes.MRInstrumentation `
	-Script {				
		if(!$NoMonitoring)
		{
			Invoke-ExecutionScript -ExecutionScript $importMRModuleExecution
			Invoke-ExecutionScript -ExecutionScript $setMRDefaultValuesExecution   	
			New-MRInstrumentationDeployment -ErrorAction Stop		
			Invoke-ExecutionScript -ExecutionScript $removeMRModuleExecution
		}        
	}	
	
$detectMRInstalledExecution = New-ScriptExecution -Name 'Detect MR Installed' `
	-ErrorCode $ErrorCodes.TestMRInstalled `
	-Script {
		return Test-MRInstalled
	}

$scriptParams = $PSBoundParameters
$installMRExecution = New-ScriptExecution -Name 'Install MR' `
	-ErrorCode $ErrorCodes.InstallManagementReporter `
	-Script {
		$installScript = "$PSScriptRoot\InstallManagementReporter.ps1"
		$installParams = Remove-InvalidParameters -Command $installScript -Parameters $scriptParams -SuppressWarnings
		. $installScript @installParams
	}

$importMRModuleExecution = New-ScriptExecution -Name 'Import MR Module' -UseAppDomain `
	-ErrorCode $ErrorCodes.ImportMRDeploy `
	-Functions @('Write-LogMessage', 'Get-MRFilePaths', 'Import-MRDeployModule') `
	-Script {
		Import-MRDeployModule
	}

$displayMRModuleVersionExecution = New-ScriptExecution -Name 'Display Module Version' -UseAppDomain `
	-ErrorCode $ErrorCodes.DisplayMRDeploy `
	-Functions @('Write-LogMessage', 'Show-MRDeployVersion') `
	-Script {
		Show-MRDeployVersion
	}

$removeMRModuleExecution = New-ScriptExecution -Name 'Remove MR Module' -UseAppDomain `
	-ErrorCode $ErrorCodes.RemoveMRModule `
	-Functions @('Write-LogMessage') `
	-Script {
		Write-LogMessage -Message "Removing imported module $ModuleName"
		Remove-Module $ModuleName
	}

$removeMRInstallExecution = New-ScriptExecution -Name 'Remove MR Install' `
	-ErrorCode $ErrorCodes.UninstallManagementReporter `
	-Script {
		if(!$NoInstall)
		{
			Uninstall-MRServer
		}
		else
		{
			Write-LogMessage -Message 'Skipping MR uninstall'
		}
	}
#endregion

#region Assemble Commands
<#
Implementation Notes:
* An AppDomain will exist for sequential executions (series) that need it
* If you have a series of executions that require an AppDomain followed by an execution that doesn't require it and then another series, there will be two AppDomains
* If you don't have an ExecuteOnCondition, it's safe to not specify anything (just don't specify null)
#>
# TODO honor the NoRemoval flag (we don't do this today except inside MRDeploy)
$removalExecutionGroup = New-ExecutionGroup -Name 'MR Removal'
$removalExecutionGroup.ExecuteOnCondition = $detectMRInstalledExecution
$removalExecutionGroup.ScriptExecutions = @($importMRModuleExecution, $displayMRModuleVersionExecution, $setMRDefaultValuesExecution, $removeMRSetupExecution, $removeMRModuleExecution, $removeMRInstallExecution)

$executionGroups = @($removalExecutionGroup)
if(!$Remove)
{
	$installationExecutionGroup = New-ExecutionGroup -Name 'MR Installation'
	$installationExecutionGroup.ScriptExecutions = @($installMRExecution, $importMRModuleExecution, $displayMRModuleVersionExecution, $setMRDefaultValuesExecution, $newMRSetupExecution, $removeMRModuleExecution)
	
	$executionGroups += $installationExecutionGroup
	
	$instrumentationExecutionGroup = New-ExecutionGroup -Name 'MR Instrumentation'
	$instrumentationExecutionGroup.ScriptExecutions = @($newMRInstrumentationDeploymentExecution)   
	
	$executionGroups += $instrumentationExecutionGroup
}
#endregion

#region Define ExecutExecutionScriptsInAppDomain
function Invoke-ExecutExecutionScriptsInAppDomain
{
	Param
	(
		[PSCustomObject[]]
		[ValidateNotNull()]
		$ExecutionScripts,

		[hashtable]
		[ValidateNotNull()]
		$Variables
	)

	[string[]]$scriptContent = @()

	$loadedFunctions = @()
	$functionScript = New-Object -TypeName 'System.Text.StringBuilder'
	foreach($executionScript in $ExecutionScripts)
	{
		foreach($func in $executionScript.Functions)
		{
			if($func -in $loadedFunctions)
			{
				# Skip if already loaded
				continue
			}

			# Extra return at the end is deliberate 
			$functionContent = @"
function $func
{
	$((Get-Content function:\$func).ToString().Trim())
}

"@
			Write-LogMessage "Adding function '$func' to AppDomain"
			[void]$functionScript.Append($functionContent)
			$loadedFunctions += $func
		}
	}

	if($functionScript.Length -gt 0)
	{
		$scriptContent += $functionScript.ToString()
	}

	foreach($executionScript in $ExecutionScripts)
	{
		Write-LogMessage "Adding execution '$($executionScript.Name)' to AppDomain"
		$scriptContent += "      $($executionScript.Script.ToString().Trim())"
	}

	Write-LogMessage 'Executing scripts in AppDomain'
	Invoke-PSAppDomain -ScriptText $scriptContent -Variables $Variables -ErrorAction Stop -Verbose *>&1 | Out-Log
	Write-LogMessage 'Finished executing scripts in AppDomain'
}
#endregion

#region Execute Commands
$lastExecutedExecutionGroup = $null
try
{
	foreach($executionGroup in $executionGroups)
	{
		Write-LogMessage "Starting execution group '$($executionGroup.Name)'"
		
		if($executionGroup.ExecuteOnCondition -ne $null -and 'Script' -in ($executionGroup.ExecuteOnCondition | Get-Member).Name -and $executionGroup.ExecuteOnCondition.Script -ne $null)
		{
			Write-LogMessage "Validating execution group condition '$($executionGroup.ExecuteOnCondition.Name)'" 
			$lastExecutedExecutionGroup = $executionGroup.ExecuteOnCondition
			$result = Invoke-ExecutionScript -ExecutionScript $executionGroup.ExecuteOnCondition -ReturnLastOutput
			if(!$result)
			{
				Write-LogMessage 'Stopping execution group due to ExecuteOnCondition = false'
				continue
			}
		}

		for($i = 0; $i -lt $executionGroup.ScriptExecutions.Count; $i++)
		{
			$scriptExecution = $executionGroup.ScriptExecutions[$i]
			if(!$NoAppDomain -and $scriptExecution.UseAppDomain)
			{
				# Count till you reach first UseAppDomain = false
				$lastUseAppDomain = $i
				for($j = $i+1;$j -lt $executionGroup.ScriptExecutions.Count;$j++)
				{
					if($executionGroup.ScriptExecutions[$j].UseAppDomain)
					{
						$lastUseAppDomain = $j
					}
					else
					{
						break
					}
				}

				if($i -eq $lastUseAppDomain)
				{
					$useAppDomainScriptExecutions = @($scriptExecution)
				}
				else
				{
					$useAppDomainScriptExecutions = $executionGroup.ScriptExecutions[$i..$lastUseAppDomain]
				}

				# Because a batch of execution groups are executed we have to null out this variable because we don't know the last one to execute is
				$lastExecutedExecutionGroup = $null
				Invoke-ExecutExecutionScriptsInAppDomain -ExecutionScripts $useAppDomainScriptExecutions -Variables $variables

				$i = $lastUseAppDomain
			}
			else
			{
				$lastExecutedExecutionGroup = $scriptExecution
				Invoke-ExecutionScript -ExecutionScript $scriptExecution
			}
		}
	}
}
catch
{
	if($logFilePath)
	{
		try
		{
			Write-ErrorDetail -ErrorThrown $Error[0] -LogPath $logFilePath
		}
		catch
		{
			Write-FormatListToLogFilePath -Message 'Failed to output error' -MessageObject $Error[0] -LogFilePath $logFilePath
			# Eat the exception
		}
	}

	# Duplicated from ScriptSetup.ps1 in Invoke-ExecutionScript, this file is planned for deletion (note: $lastExecutedExecutionGroup is unique)
	if($lastExecutedExecutionGroup)
	{
		[int]$exitCode = $lastExecutedExecutionGroup.ErrorCode
		[string]$exitMessage = "Failed executing $($lastExecutedExecutionGroup.Name)"
		if($lastExecutedExecutionGroup.ErrorCodeHandler -ne $null -and $lastExecutedExecutionGroup.ErrorCodeHandler.ToString().Length -gt 0)
		{
			$errorCodeFromHandler = & $lastExecutedExecutionGroup.ErrorCodeHandler $errorCaught
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
finally
{
	if(!$NoAppDomain)
	{
		Find-PsAppDomainCmdlet -Remove
	}

	# Sleep for 5 seconds to all ETW events and logs to be flushed
	Start-Sleep -Seconds 5

	# Dump out the logs
	Copy-DeploymentLogFile -FolderForLogs $mrDeploymentLogsFolder -StartRange $StartTime
	
	# Dump out Event Logs
	Copy-MREventLogs -FolderForLogs $mrDeploymentLogsFolder -StartRange $StartTime
}
#endregion

# SIG # Begin signature block
# MIIjgwYJKoZIhvcNAQcCoIIjdDCCI3ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBg8HcRKsZ3W9k6
# JDGgVqbUBDtMW6cavCQB9rU/EKnpHaCCDYEwggX/MIID56ADAgECAhMzAAACUosz
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWDCCFVQCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgHXw+dbxn
# oMHNdx93VcFUg0Fnk20GXzV8yzOPn1ZXyW8wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQB6AIoQdIGcsFYWt7qkmEEFZiAeDM2UtwCAPsmqGn1B
# 3qfvkk7v60JNQNJxymbs7boZpXWxVF2g02GLvOp59uTC42UEgiv8M5ctY5ZbqjAV
# 3if/7OQrTVzzuOJweM+byh8ZcEPfu3KDJudtFk1tGe1VUyY4Fdz61HobAK4I/nUE
# Mukr4Yybm2ymg5d5z5TK9bbxbdLofWSJnliIgIAHmxfkohseG+LZvL4S0na4XVJc
# n6l5KQLcDJLjt6rvlMSNN5QjvosQOBzOBb6iFaU2mBc1nwHcTUgcS9cdkyeViTb3
# FahXIrpwt5ypNzwOSuCh6IhvZSyEfOiA5SZNqJKXz1xGoYIS4jCCEt4GCisGAQQB
# gjcDAwExghLOMIISygYJKoZIhvcNAQcCoIISuzCCErcCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIBSZNcH/fnBPGZ2O0G/ykoaeUdHgvssj1a95DIbx
# zxobAgZhkuF1F7gYEzIwMjExMjAxMDgzODEwLjE1N1owBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOTCCBPEwggPZoAMCAQICEzMAAAFSMEtdiazmcEcAAAAAAVIw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNjA1WhcNMjIwMjExMTgyNjA1WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEy
# NUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuzG6EiZh0taCSbswMiupMTYnbboFz
# jj1DuDbbvT0RXKBCVl/umA+Uy214DmHiFhkeuRdlLB0ya5S9um5aKr7lBBqZzvtK
# gGNgCRbDTG9Yu6kzDzPTzQRulVIvoWVy0gITnEyoJ1O3m5IPpsLBNQCdXsh+3TZF
# 73JAcub21bnxm/4sxe4zTdbdttBrqX8/JJF2VEnAP+MBvF2UQSo6XUAaTKC/HPDP
# Cce/IsNoAxxLDI1wHhIlqjRBnt4HM5HcKHrZrvH+vHnihikdlEzh3fjQFowk1fG7
# PVhmO60O5vVdqA+H9314hHENQI0cbo+SkSi8SSJSLNixgj0eWePTh7pbAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUhN2u2qwj1l2c2h/kULDuBRJsexQwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAVcUncfFqSazQbDEXf3d10/upiWQU5HdTbwG9v9be
# VIDaG4oELyIcNE6e6CbOBMlPU+smpYYcnK3jucNqChwquLmxdi2iPy4iQ6vjAdBp
# 9+VFWlrBqUsNXZzjCpgMCZj6bu8Xq0Nndl4WyBbI0Jku68vUNG4wsMdKP3dz+1Mz
# k9SUma3j7HyNA559do9nhKmoZMn5dtf03QvxlaEwMAaPk9xuUv9BN8cNvFnpWk4m
# LERQW6tA3rXK0soEISKTYG7Ose7oMXZDYPWxf9oFhYKzZw/SwnhdBoj2S5eyYE3A
# uF/ZXzR3hdp3/XGzZeOdERfFy1rC7ZBwhDIajeFMi53GnzCCBnEwggRZoAMCAQIC
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
# X4/edIhJEqGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAv26eVJaumcmTchd6hqayQMNDXluggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOVRJgowIhgPMjAy
# MTEyMDEwNjM2NThaGA8yMDIxMTIwMjA2MzY1OFowdDA6BgorBgEEAYRZCgQBMSww
# KjAKAgUA5VEmCgIBADAHAgEAAgIDPTAHAgEAAgISpDAKAgUA5VJ3igIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBAJmYd8pA87GPpZ5Vgt88XoVm2xUCBcO067q5
# Kp8m+B/WX1I/6U1X7EfJR/oGwmolycuz9FoosBwwJBQjsjJ1SB9TmReFRXFHcb1Q
# 6Q1iQmArYsZmX9L/6aRYN4a6PyAyMLOnKQ49n29Pihjw53gEBlEUk4TQVi4kfktN
# 7kalFfq5MYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAFSMEtdiazmcEcAAAAAAVIwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg+GgpMltGUyIh
# YlF1ZPocM1/Y8z7Cp9TO+rL58dblg0YwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCCT7lzHo4slUIxfEGp8LXQNik/ecK6vuuGWIcmBrrsnpjCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABUjBLXYms5nBHAAAAAAFS
# MCIEIHeQFLa97+j/941vHPEqMyS/U9VWXPPUeIs6wIzslwyuMA0GCSqGSIb3DQEB
# CwUABIIBACBCEs9sAkK/oCeXvL6YL139XW68yk+hzWPf/03fHqWbPx8EjfzwqTOM
# p+9ddgR/IYaLtBQQlOMud0ZE3Pwud7d8pPIK1TNUKaD5ryFhGxO3IXnUvCLHs2RW
# UfQFFGGtykwOn+fCdvtvN+m+DFGb08Y0IdXfRLR1iDzyK3LXlnlvULp28X7sUBI4
# oFi/WgLPPE8hIt/e4K6cZwZzip1fQi6AoYXxn6NmCPrQ80ObpgwN8gPUsUXxIiTa
# rSPtCyNK5vogJ8tE8FQgUkPgLA8PZW8tgu6wnXPSJd+E/X3tfS0js+B0V8vqE+dy
# vzhXUXssUF5DGlFGcA2vbx0JkL4Z3J4=
# SIG # End signature block
