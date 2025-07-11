param
(
    [parameter(Position = 0, Mandatory = $false)]
    [boolean]$useServiceFabric = $false
)

if (!$useServiceFabric)
{
    Import-Module WebAdministration
}

$Global:FileLockCheckDll_Path = "$PSScriptRoot/../Microsoft.Dynamics.AX.FileLockCheck.dll"

<#
.SYNOPSIS
    Locate the file lock check dll inside deployable package
.Return
    True if the dll is found
#>
function Locate-FileLockCheckDll
{
    if (Test-Path $Global:FileLockCheckDll_Path)
    {
        return $true
    }
    #if this script is not in AOSService folder, trying to find if AOSService is available
    $dllPath = "$PSScriptRoot/../../AOSService/Microsoft.Dynamics.AX.FileLockCheck.dll"
    
    if (Test-Path $dllPath)
    {
        $Global:FileLockCheckDll_Path = $dllPath
        return $true
    }
    return $false
}

<#
.SYNOPSIS
    Call this to initialize the log for use in Write-ServicingLog.

.NOTES
    Because this module is being imported with the -Force switch from multiple scripts, it must use
    global scope variable to preserve the values across imports.

.PARAMETER LogDir
    Specify the path of the log directory to write to. Set to the empty string to disable
    writing to a log file for subsequent calls to Write-ServicingLog.

.PARAMETER LogFileName
    Specify the name of the log file to write to. If not set, the file name will be determined
    from the $MyInvocation.PSCommandPath or if null, set to Servicing_<TimeStamp>.log.
#>
function Set-ServicingLog([string]$LogDir, [string]$LogFileName)
{
    if ($PSBoundParameters["LogDir"] -and $LogDir -ne $null)
    {
        # Use specified log directory.
        $Global:ServicingLogDir = $LogDir

        if ($PSBoundParameters["LogFileName"] -and $LogFileName -ne $null)
        {
            # Use specified log file name.
            $Global:ServicingLogFileName = $LogFileName
        }
        else
        {
            if ($MyInvocation.PSCommandPath)
            {
                # Use the top level script name as the log file name.
                $ScriptFileName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
                $Global:ServicingLogFileName = "$($ScriptFileName).log"
            }
            else
            {
                # Use default if somehow not run from a script.
                $Global:ServicingLogFileName = "Servicing_$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss')).log"
            }
        }
    }

    # Set full log file path or disable logging to file if not set.
    if ($Global:ServicingLogDir -and $Global:ServicingLogFileName)
    {
        # Ensure that the log directory exists.
        if (!(Test-Path -Path $Global:ServicingLogDir -ErrorAction SilentlyContinue))
        {
            New-Item -Path $Global:ServicingLogDir -ItemType Directory -Force | Out-Null
        }

        $Global:ServicingLogFilePath = Join-Path -Path $Global:ServicingLogDir -ChildPath $Global:ServicingLogFileName
    }
    else
    {
        $Global:ServicingLogFilePath = $null
    }
}

<#
.SYNOPSIS
    Gets the full path to the log file currently set for use in Write-ServicingLog.
#>
function Get-ServicingLog()
{
    return $Global:ServicingLogFilePath
}

<#
.SYNOPSIS
    Write a message or error record to a log file and/or to output.
    Call Set-ServicingLog -LogDir "<Path to logs directory>" to initialize the log file.

.PARAMETER Message
    The message or error record to log.

.PARAMETER ExcludeTimestamp
    Exclude the timestamp prefix.

.PARAMETER Vrb
    Message is verbose and should only go to log file and not to output.
#>
function Write-ServicingLog($Message, [switch]$ExcludeTimestamp, [Alias("V", "NoConsole")][switch]$Vrb)
{
    $LogMessage = ""

    if ($Message -is [System.String])
    {
        $LogMessage += $Message
    }
    elseif ($Message -is [System.Management.Automation.ErrorRecord])
    {
        # Using "Format-List -Force" which will provide
        # detailed information regarding the exception.
        $LogMessage += $($Message | Format-List -Force | Out-String)
    }
    else
    {
        # Using ($Message | Out-String) to get object to string formatting that matches the original
        # behavior of just executing Write-Output $Message.
        # ex. when $Message is a powershell error record,
        # Out-String returns both the error message and call stack.
        $LogMessage += ($Message | Out-String)
    }

    # Get the message timestamp in UTC.
    [DateTime]$Timestamp = [DateTime]::UtcNow

    # Write to log file path if it is defined.
    $LogFilePath = Get-ServicingLog
    if ($LogFilePath)
    {
        try
        {
            # Prefix long timestamp in log file.
            if (!$ExcludeTimestamp)
            {
                Add-Content -Path $LogFilePath -Value "[$($Timestamp.ToString('u'))] $($LogMessage)" -ErrorAction SilentlyContinue
            }
            else
            {
                Add-Content -Path $LogFilePath -Value $LogMessage -ErrorAction SilentlyContinue
            }
        }
        catch
        {
            # Output error in the rare case this fails.
            Write-Debug "Write-ServicingLog error: $($_)"
        }
    }

    # Verbose messages do not go to output.
    if (!$Vrb)
    {
        # Prefix short timestamp in output.
        if (!$ExcludeTimestamp)
        {
            Write-Output "[$($Timestamp.ToString('HH:mm:ss'))] $($LogMessage)"
        }
        else
        {
            Write-Output $LogMessage
        }
    }
}

<#
.SYNOPSIS
    Write Runbook Script Traces.

.PARAMETER Message
    Write a message or error to a log file.

.PARAMETER Component
    Component name for which trace needs to log.

.PARAMETER RunbookId
    Runbook ID for which trace message needs to log.
#>
function EventWrite-RunbookScriptTrace([string]$Message, [string]$Component, [Parameter(Mandatory = $false)][string]$RunbookId)
{
    try {
          $packageRootPath = "$(split-Path -parent $PSScriptRoot)" | Split-Path -Parent
          $job = Start-Job -ScriptBlock {
              param($packageRootPath, $Message, $Component, $ScriptLineNumber, $CommandName, $RunbookId)
              
              Add-Type -path "$packageRootPath\Microsoft.Dynamics.ApplicationPlatform.Development.Instrumentation.dll"
              [Microsoft.Dynamics.ApplicationPlatform.Instrumentation.ServicingEventSource]::EventWriteRunbookScriptTrace(
              $RunbookId, $Component, $CommandName ,$PSScriptRoot, $ScriptLineNumber, "1.0.0", $Message)
                            
           } -ArgumentList $packageRootPath, $Message, $Component, $MyInvocation.ScriptLineNumber, $MyInvocation.MyCommand.Name, $RunbookId
          
          Wait-Job -Job $job | Out-Null
          Receive-Job -Job $job
          
          if($job.JobStateInfo.State -eq 'Failed')
          {
            $job | %{$_.Error} | %{Write-ServicingLog $_}
          }
    }
    catch {
       Write-Host $_
      }
}

<#
.SYNOPSIS
    Add a script progress step to the progress collection.

.PARAMETER ProgressStep
    The name of the progress step to add.
#>
function Add-ScriptProgress
{
    [CmdletBinding()]
    Param([string]$ProgressStep)
    
    $mustInitScriptProgressMsg = "ScriptProgress must be initialized with the Initialize-ScriptProgress for the appropriate scope before attempting to set progress."

    if (($null -eq $executionProgress) -or ($null -eq $executionProgressFile) -or ($null -eq $executionProgressFileLocal))
    {
        Write-Error "One or more 'executionProgress*' variables are not defined. $mustInitScriptProgressMsg"
        return
    }

    if (!(Test-Path $executionProgressFile))
    {
        Write-Error "Execution progress file at [$executionProgressFile] does not exist. $mustInitScriptProgressMsg"
        return
    }

    if (!(Test-Path $executionProgressFileLocal))
    {
        Write-Error "Local execution progress file at [$executionProgressFileLocal] does not exist. $mustInitScriptProgressMsg"
        return
    }

    if (!$executionProgress.$ProgressStep)
    {
        $executionProgress.$ProgressStep = [System.DateTime]::UtcNow.ToString("O")
    }

    $executionProgress | ConvertTo-Json | Out-File $executionProgressFile -Force
    $executionProgress | ConvertTo-Json | Out-File $executionProgressFileLocal -Force
}

<#
.SYNOPSIS
    Initializes the script progress file used for tracking progress of a script or set of related scripts.

.PARAMETER ProgressFile
    The file path where the progress is tracked.

.PARAMETER Scope
    The scope the progress collection should be available in.
#>
function Initialize-ScriptProgress
{
    [CmdletBinding()]
    Param([string]$ProgressFile, [string]$Scope = "")
    
    if ([string]::IsNullOrWhitespace($Scope))
    {
        $Scope = 1
    }

    try 
    {
        # Define the variable for the progress file in the target location
        if (!(Get-Variable -Scope $Scope -Name "executionProgressFile" -ErrorAction SilentlyContinue))
        {
            New-Variable -Scope $Scope -Name "executionProgressFile"
        }

        # Define the variable for the progress file in the local location (adjacent to the executing script)
        if (!(Get-Variable -Scope $Scope -Name "executionProgressFileLocal" -ErrorAction SilentlyContinue))
        {
            New-Variable -Scope $Scope -Name "executionProgressFileLocal"
        }

        $localProgressFile = Join-Path -Path $PSScriptRoot -ChildPath (Split-Path -Path $ProgressFile -Leaf)
        Set-Variable -Name "executionProgressFile" -Scope $Scope -Value $ProgressFile
        Set-Variable -Name "executionProgressFileLocal" -Scope $Scope -Value $localProgressFile

        if (!(Get-Variable -Name "executionProgress" -Scope $Scope -ErrorAction SilentlyContinue))
        {
            New-Variable -Scope $Scope -Name "executionProgress"
        }

        $scriptProgressTable = @{ }

        # Initialize the progress table if the progress file exists at the specified path but also was initialized previously in the
        # local script path. This works around an issue where the staging could have been created previously, the package updated, 
        # and the pre-processing re-executed. In that case, the updated package would overwrite the previous local progress file
        # forcing the progress table to be initialized as empty.
        if ((Test-Path $ProgressFile) -and (Test-Path $localProgressFile))
        {
            $scriptProgressTableTmp = Get-Content $ProgressFile | ConvertFrom-Json
            $scriptProgressTableTmp.psobject.properties | Foreach-Object { $scriptProgressTable[$_.Name] = $_.Value }
        }
        else 
        {
            if (Test-Path $ProgressFile)
            {
                Remove-Item $ProgressFile -Force
            }

            if (Test-Path $localProgressFile)
            {
                Remove-Item $localProgressFile -Force
            }

            $progressFileParent = Split-Path $ProgressFile -Parent
            $progressFileLocalParent = Split-Path $localProgressFile -Parent

            if (!(Test-Path $progressFileParent -PathType Container))
            {
                New-Item $progressFileParent -ItemType Container | Out-Null
            }
        
            if (!(Test-Path $progressFileLocalParent -PathType Container))
            {
                New-Item $progressFileLocalParent -ItemType Container | Out-Null
            }

            $scriptProgressTable | ConvertTo-Json | Out-File $ProgressFile -Force
            $scriptProgressTable | ConvertTo-Json | Out-File $localProgressFile -Force
        }

        Set-Variable -Name "executionProgress" -Scope $Scope -Value $scriptProgressTable
        
    }
    catch
    {
        # Treat any terminating error in the cmdlet scope as a non-terminating error. 
        # Let the parent handle appropriately through ErrorAction
        Write-Error "Unable to initialize the script progress file [$ProgressFile]. Details: $($_ | Format-List -Force)"
    }
}

<#
.SYNOPSIS
    Tests if progress has been made for the specified progress step.

.PARAMETER ProgressStep
    The progress step name to test.
#>
function Test-ScriptProgress
{
    [CmdletBinding()]
    Param([string]$ProgressStep)

    if (($null -eq $executionProgress) -or ($null -eq $executionProgressFile) -or ($null -eq $executionProgressFileLocal))
    {
        return $false
    }

    if (!(Test-Path $executionProgressFile) -or !(Test-Path $executionProgressFileLocal))
    {
        return $false
    }

    $progressStepValue = $executionProgress.$ProgressStep

    if (![string]::IsNullOrWhiteSpace($progressStepValue))
    {
        return $true
    }

    return $false
}

<#
.SYNOPSIS
    Gets the script progress timestamp for the specified progress step. Returns null if the step was not found.

.PARAMETER ProgressStep
    The pregress step name.
#>
function Get-ScriptProgress
{
    [CmdletBinding()]
    Param([string]$ProgressStep)

    if (Test-ScriptProgress $ProgressStep)
    {
        return $executionProgress.$ProgressStep
    }

    return $null
}

<#
.SYNOPSIS
    Copies the current script progress file to the specified location.

.PARAMETER Destination
    The destination file path.
#>
function Copy-ScriptProgressFile
{
    [CmdletBinding()]
    Param([string]$Destination)

    if (($null -eq $executionProgressFile) -or !(Test-Path $executionProgressFile))
    {
        Write-Warning "The source progress file at [$executionProgressFile] was not found. Skipping copy."
        return
    }

    Copy-Item $executionProgressFile $Destination -Force
}

<#
.SYNOPSIS
    Execute a powershell code block with retry mechanism 

.PARAMETER codeBlock
    The content of the powershell script to be executed.
.PARAMETER blockMessage
    The name of the script block
.PARAMETER maxRetry
    Maximum retry count.
.PARAMETER sleepTimeInSecond
    Time interval in second between two retries.
#>
function Invoke-WithRetry([ScriptBlock]$codeBlock, [string]$scriptName = "", [int]$maxRetry = 5, [int]$sleepTimeInSecond = 10)
{    
    Write-ServicingLog "$scriptName`: Starting execution with retry"
    for ($retry = 0; $retry -lt $maxRetry; $retry++)
    {
        try
        {
            $codeBlock.Invoke()
            break;
        }
        catch
        {
            if($retry -lt $maxRetry - 1)
            {
                Write-ServicingLog "Exception in $scriptName`: $_"              
                Write-ServicingLog "Sleeping $sleepTimeInSecond seconds before retrying"
                Start-Sleep -Seconds $sleepTimeInSecond
            }
            else
            {
                Write-ServicingLog "Exception in $scriptName`: $_" 
                throw 
            }
        }
    }
    Write-ServicingLog "$scriptName`: Completed execution in $maxRetry iterations"
}


<#
.SYNOPSIS
    Attempts to get the runbook ID for the current package. Null if the ID cannot be determined.
#>
function Get-RunbookId
{
    $packageRoot = Get-PackageRoot

    if ([string]::IsNullOrEmpty(($packageRoot)))
    {
        return $null
    }

    #First find the name of the runbook working folder in the package
    $workingFolder = Join-Path -Path $packageRoot -ChildPath "RunbookWorkingFolder"
    if (Test-Path ($workingFolder))
    {
        $firstDirectory = Get-ChildItem $workingFolder -Directory | Select-Object -First 1
        if ($firstDirectory)
        {
            return $firstDirectory.Name
        }
    }

    #If the working folder isn't found, look for the runbook in the root of the package
    Get-ChildItem $packageRoot -File -Filter "*.xml" | ForEach-Object {
        $xmlFile = [xml](Get-Content $_.FullName)
        $runbookIdNode = $xmlFile.SelectSingleNode("/RunbookData/RunbookID")
        if ($runbookIdNode -and ![string]::IsNullOrWhiteSpace($runbookIdNode."#text"))
        {
            return $runbookIdNode."#text"
        }
    }

    #If it still isn't found, return null
    return $null
}

<#
.SYNOPSIS
    Attempts to get the deployable package root. Null if the root cannot be determined.
#>
function Get-PackageRoot
{
    $maxDepth = 5
    $currentPath = $PSScriptRoot

    for ($i = 5; $i -gt 0; $i--)
    {
        if ([string]::IsNullOrWhiteSpace($currentPath))
        {
            return $null
        }
        elseif (Test-Path (Join-Path -Path $currentPath -ChildPath "AxUpdateInstaller.exe"))
        {
            return $currentPath
        }
        else
        {
            $currentPath = Split-Path $currentPath -Parent
        }
    }
}

<#
.SYNOPSIS
    Stop a service and set startup type to disabled to prevent unintentional starts.
#>
function Stop-ServiceAndDisableStartup([string]$ServiceName, [int]$MaxWaitSec = 300)
{
    $Service = Get-Service -Name $ServiceName -ErrorAction "SilentlyContinue"
    if ($Service)
    {
        # Start by disabling service.
        Set-Service -Name $ServiceName -startupType Disabled

        # Stop service if not already stopped.
        if ($Service.Status -ine "Stopped")
        {
            Write-ServicingLog "Stopping $($ServiceName) service with status $($Service.Status)..." -Vrb
            $Service | Stop-Service -ErrorAction "Stop"

            $StopWatch = [System.Diagnostics.StopWatch]::StartNew()

            # Wait for service to reach stopped status. 
            while ($Service.Status -ine "Stopped" -and $StopWatch.Elapsed.TotalSeconds -lt $MaxWaitSec)
            {
                Start-Sleep -Seconds 1
                $Service = Get-Service -Name $ServiceName
            }

            $StopWatch.Stop()

            if ($Service.Status -ine "Stopped")
            {
                throw "Unable to stop the $($ServiceName) service with status $($Service.Status) within the $($MaxWaitSec) second timeout."
            }
            else
            {
                Write-ServicingLog "Stopped the $($ServiceName) service in $([Math]::Round($StopWatch.Elapsed.TotalSeconds)) seconds." -Vrb
            }
        }
        else
        {
            Write-ServicingLog "The $($ServiceName) service is already stopped." -Vrb
        }
    }
    else
    {
        Write-ServicingLog "The $($ServiceName) service could not be found and thus not stopped or disabled." -Vrb
    }
}

<#
.SYNOPSIS
    Returns true if the current user is a member of the built-in administrators group.
#>
function Test-IsRunningAsAdministrator()
{
    [bool]$IsAdministrator = $false

    [Security.Principal.WindowsPrincipal]$Principal = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($Principal)
    {
        $IsAdministrator = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    return $IsAdministrator
}

function Create-ZipFiles(
    [string] $sourceFolder = $(Throw 'sourceFolder parameter required'),
    [string] $destFile = $(Throw 'destFile parameter required'),
    [string] $filetypesExcluded,
    [string] $folderExcluded,
    [string] $fileFilter,
    [string] $zipLogDir)
{
    Set-Variable zipLocation -Option Constant -Value (Join-Path $env:SystemDrive "DynamicsTools\7za.exe")

    if (-Not (Test-Path $sourceFolder))
    {
        throw "Path not found: $sourceFolder"
    }

    if (Test-Path $destFile)
    {
        Remove-Item $destFile -Force
    }

    Push-Location $sourceFolder
    $argumentList = "a -mx1 -r -y"

    if (![string]::IsNullOrEmpty($filetypesExcluded))
    {
        $argumentList = $argumentList + " -x!$filetypesExcluded"
    }

    if (![string]::IsNullOrEmpty($folderExcluded))
    {
        $argumentList = $argumentList + " -xr!$folderExcluded"
    }

    $argumentList = $argumentList + " $destFile"

    if (![string]::IsNullOrEmpty($fileFilter))
    {
        $argumentList = $argumentList + " $fileFilter"
    }

    $ZipLog = Join-Path $PSScriptRoot tempZipLog.txt
    if (Test-Path $ZipLog)
    {
        Remove-Item $ZipLog
    }

    $process = Start-Process $zipLocation -ArgumentList $argumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $ZipLog #7zip doesn't have stderr
    try { if (!($process.HasExited)) { Wait-Process $process } } catch { }

    Pop-Location
    if ($process.ExitCode -ne 0)
    {
        # If zipLogDir parameter was passed, copy 7zip failure logs to zipLogDir before exiting
        if (Test-Path $zipLogDir)
        {
            Copy-Item $ZipLog -Destination (Join-Path $zipLogDir "ZipLog_$([DateTime]::UtcNow.ToString("yyyyMMddHHmmss")).log")
        }

        throw "fail to generate zip archive: $destFile, check the log file for more detail: $ZipLog"
    }
    if (Test-Path $ZipLog)
    {
        Remove-Item $ZipLog
    }
}

function KillProcessLockingFolder(
    [string] $folder = $(Throw 'Folder parameter required'))
{
    #detect if any process is locking file
    Write-Output "Finding and terminating processes accessing files under $folder"
    $ProcessesLockingAOS = Get-Process | Where-Object { $_.Modules.FileName -like "$folder\*" }
    $ProcessesLockingAOS

    foreach ($Process in $ProcessesLockingAOS)
    {
        Stop-Process -Force -Id $Process.Id
    }
}

function KillAllOtherUserSession()
{
    $sessions = &query.exe user
    if ($sessions.count -gt 0)
    {
        $header = $sessions[0];

        foreach ($session in $sessions)
        {
            if ((! $session.StartsWith('>')) -and (! $session.StartsWith($header)))
            {
                $option = [System.StringSplitOptions]::RemoveEmptyEntries
                $name = $session.Split(' ', $option)[0]
                $SubString = $session.Substring($header.IndexOf("ID") - 3)
                $sid = $SubString.Split(' ', $option)[0]
                Write-Output "terminate session for user: $name sid: $sid"
                & { reset.exe session $sid }

            }
        }
    }
}

function Create-ZipFiles-FromFileList(
    [string[]] $fileList = $(Throw 'fileList parameter required'),
    [string] $destFile = $(Throw 'destFile parameter required'))
{
    Set-Variable zipLocation -Option Constant -Value (Join-Path $env:SystemDrive "DynamicsTools\7za.exe")

    foreach ($element in $fileList)
    {
        if (-Not (Test-Path $element))
        {
            throw "Path not found: $element"
        }
    }

    if (Test-Path $destFile)
    {
        Remove-Item $destFile -Force
    }

    $argumentList = "a" + " $destFile"

    foreach ($element in $fileList)
    {
        $argumentList = $argumentList + " $element"
    }

    $ZipLog = Join-Path $PSScriptRoot tempZipLog.txt
    if (Test-Path $ZipLog)
    {
        Remove-Item $ZipLog
    }

    $process = Start-Process $zipLocation -ArgumentList $argumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $ZipLog #7zip doesn't have stderr
    try { if (!($process.HasExited)) { Wait-Process $process } } catch { }

    if ($process.ExitCode -ne 0)
    {
        throw "fail to generate zip archive: $destFile, check the log file for more detail: $ZipLog"
    }
    if (Test-Path $ZipLog)
    {
        Remove-Item $ZipLog
    }
}

function Unpack-ZipFiles(
    [string] $sourceFile = $(Throw 'sourceFile parameter required'),
    [string] $destFolder = $(Throw 'destFolder parameter required'))
{
    Set-Variable zipLocation -Option Constant -Value (Join-Path $env:SystemDrive "DynamicsTools\7za.exe")

    if (-Not (Test-Path $sourceFile))
    {
        throw "File not found: $sourceFile"
    }

    if (-Not (Test-Path $destFolder))
    {
        throw "Path not found: $destFolder"
    }
    Push-Location $destFolder
    $argumentList = "x -y $sourceFile"

    $process = Start-Process $zipLocation -ArgumentList $argumentList -NoNewWindow -Wait -PassThru
    try { if (!($process.HasExited)) { Wait-Process $process } } catch { }

    Pop-Location
    if ($process.ExitCode -ne 0)
    {
        $argumentList
        throw "fail to extract zip archive: $sourceFile"
    }
}

function Get-WebSitePhysicalPath([string]$Name = $(Throw 'Name parameter required'))
{
    if (Get-Service W3SVC | Where-Object status -ne 'Running')
    {
        #IIS service is not running, starting IIS Service.
        Start-Service W3SVC
    }

    $webSitePhysicalPath = (Get-Website | Where-Object { $_.Name -eq $Name }).PhysicalPath

    return $webSitePhysicalPath
}

function Get-AosWebSitePhysicalPath()
{
    $websiteName = Get-AosWebSiteName
    if ($websiteName)
    {
        $websitePath = Get-WebSitePhysicalPath -Name $websiteName
        if ([string]::IsNullOrWhiteSpace($websitePath))
        {
            throw "Failed to find the webroot of AOS Service website."
        }
        return $websitePath
    }
    else
    {
        throw "Failed to find the website name. Unable to determine the physical website path."
    }
}

function Get-AosServicePath()
{
    $websitePath = Get-AosWebSitePhysicalPath
    $aosWebServicePath = "$(Split-Path -parent $websitePath)"
    return $aosWebServicePath
}

function Get-AosServiceStagingPath()
{
    $aosWebServicePath = Get-AosServicePath
    $stagingFolder = Join-Path  "$(Split-Path -parent $aosWebServicePath)" "AosServiceStaging"
    return $stagingFolder
}

function Get-AosServiceBackupPath()
{
    $aosWebServicePath = Get-AosServicePath
    $stagingFolder = Join-Path  "$(Split-Path -parent $aosWebServicePath)" "AosServiceBackup"
    return $stagingFolder
}

function Reset-IIS
{
    try
    {
        Write-Host "Attempt to reset IIS"

        iisreset /stop
        
        if($?)
        {
            Write-Host "Successfully stopped IIS"
        }
        else
        {
            Write-Host "Failed to stop IIS"
        }

        Write-Host "Sleeping for 10 seconds before restarting IIS"
        Start-Sleep -Seconds 10
        
        iisreset /start

        if($?)
        {
            Write-Host "Successfully started IIS"
        }
        else
        {
            Write-Host "Failed to start IIS"
        }
    }
    catch
    {
        Write-Host "Failed to reset IIS"
    }
}

function Get-IsIISHealthyHelper
{
    $DefaultAppPoolName = "DefaultAppPool"
    $IsIISHealthy = $false

    try
    {
        Write-Host "Attempt to determine whether IIS is healthy"
        
        $scriptBlock = {
        param($appPool) 
        Get-WebAppPoolState -Name $appPool
        }

        $DefaultAppPoolStateJob = Start-Job -ScriptBlock $scriptBlock -ArgumentList $DefaultAppPoolName | Wait-Job -Timeout 30

        if(($DefaultAppPoolStateJob.State -ne "Completed"))
        {
            $DefaultAppPoolStateJob.StopJob()
            
            Write-Host "Failed to to determine whether IIS is healthy; IIS doesn't appear to be responsive"
            
            throw "Timeout occured while attempting to determine whether IIS is healthy"
        }

        return $true
    }
    catch
    {
        Write-Host "Failed to determine the state of the default app pool; IIS doesn't appear to be responsive"
    }
    
    return $IsIISHealthy
}

function Get-IsIISHealthy
([Parameter(Mandatory=$false)]
[boolean]$attemptIISResetIfUnhealthy = $false)
{
    $DefaultAppPoolName = "DefaultAppPool"
    $IsIISHealthy = $false

    $IsIISHealthy = Get-IsIISHealthyHelper
    
    if($attemptIISResetIfUnhealthy -and !$IsIISHealthy)
    {
        Reset-IIS

        $IsIISHealthy = Get-IsIISHealthyHelper
    }

    return $IsIISHealthy
}

function Get-AosWebSiteName()
{
    if (Test-Path "iis:\sites\AosService")
    {
        return "AosService"
    }
    elseif (Test-Path "iis:\sites\AosServiceDSC")
    {
        return "AosServiceDSC"
    }
    elseif (Test-Path "iis:\sites\AosWebApplication")
    {
        return "AosWebApplication"
    }
    else
    {
        throw "Failed to find the AOS website name."
    }
}

function Get-AosAppPoolName()
{
    $websiteName = Get-AosWebSiteName
    if ($websiteName)
    {
        if ($websiteName -eq "AosWebApplication")
        {
            #Non service-model deployments have a different app pool and site name
            return "AOSAppPool"
        }
        else
        {
            #Service model-based deployments have app pool and site use the same name
            return $websiteName
        }
    }
    else
    {
        throw "Failed to find the AOS website name. Unable to determine application pool name."
    }
}

function Update-IISWebSiteServerAutoStartProperty($iISWebSiteName, $serverAutoStart)
{
    # Determine if running in admin or non-admin mode.
    $IsAdmin = Test-IsRunningAsAdministrator
    
    if ($IsAdmin)
    {
        Set-ItemProperty -Path "IIS:\Sites\$iISWebSiteName" -Name serverAutoStart -Value $serverAutoStart
    }
}

function Update-IISAppPoolServerAutoStartProperty($iISAppPoolName, $serverAutoStart)
{
    # Determine if running in admin or non-admin mode.
    $IsAdmin = Test-IsRunningAsAdministrator
    
    if ($IsAdmin)
    {
        Set-ItemProperty -Path "IIS:\AppPools\$iISAppPoolName" -Name autoStart -Value $serverAutoStart
    }
}

function Update-EnableRestartForSiteAfterIISResetOrReboot([string]$IISWebSiteName = $(Throw 'Name parameter required'))
{
    Update-IISWebSiteServerAutoStartProperty -IISWebSiteName $IISWebSiteName -ServerAutoStart $true
}

function Update-EnableRestartForAppPoolAfterIISResetOrReboot([string]$IISAppPoolName = $(Throw 'Name parameter required'))
{
    Update-IISAppPoolServerAutoStartProperty -IISAppPoolName $IISAppPoolName -ServerAutoStart $true
}

function Update-DisableRestartForSiteAfterIISResetOrReboot([string]$IISWebSiteName = $(Throw 'Name parameter required'))
{
    Update-IISWebSiteServerAutoStartProperty -IISWebSiteName  $IISWebSiteName -ServerAutoStart $false
}

function Update-DisableRestartForAppPoolAfterIISResetOrReboot([string]$IISAppPoolName = $(Throw 'Name parameter required'))
{
    Update-IISAppPoolServerAutoStartProperty -IISAppPoolName $IISAppPoolName -ServerAutoStart $false
}

function Get-ProductConfigurationAppPoolName()
{

    if (Test-Path "iis:\apppools\ProductConfiguration")
    {
        return "ProductConfiguration"
    }
    else
    {
        return ""
    }
}

function Backup-WebSite(
    [ValidateNotNullOrEmpty()]
    [string]$Name = $(Throw 'Name parameter required'),

    [string]$BackupFolder)
{
    Write-Output "Executing backup for [$Name] website"

    $webroot = Get-WebSitePhysicalPath -Name $Name
    if ([string]::IsNullOrEmpty($webroot))
    {
        throw "Failed to locate physical path for [$Name] website."
    }

    if ([string]::IsNullOrEmpty($BackupFolder))
    {
        $BackupFolder = ("$PSScriptRoot\{0}_Backup" -f $Name)
    }

    $webrootBackupFolder = Join-Path $BackupFolder 'webroot'

    if (-not (Test-Path -Path $webrootBackupFolder ))
    {
        New-Item -ItemType Directory -Path $webrootBackupFolder -Force
    }

    Write-Output "Begin backup of [$Name] website at $webroot"
    Create-ZipFiles -sourceFolder $webroot -destFile (Join-Path $webrootBackupFolder 'webroot.zip')
    Write-Output "Finished executing backup for [$Name]"
}

function Restore-WebSite(
    [ValidateNotNullOrEmpty()]
    [string]$Name = $(Throw 'Name parameter required'),

    [string]$BackupFolder)
{
    Write-Output "Executing restore for [$Name] website"

    $webroot = Get-WebSitePhysicalPath -Name $Name
    if ([string]::IsNullOrEmpty($webroot))
    {
        throw "Failed to locate physical path for [$Name] website."
    }

    if ([string]::IsNullOrEmpty($BackupFolder))
    {
        $BackupFolder = ("$PSScriptRoot\{0}_Backup" -f $Name)
    }

    $webrootBackupFolder = Join-Path $BackupFolder 'webroot'

    if (-not (Test-Path -Path $webrootBackupFolder ))
    {
        throw "Failed to find the backup file for website [$Name], restore aborted."
    }

    Write-Output "Removing website data at $webroot"
    Remove-Item -Path "$webroot\*" -Recurse -Force

    Write-Output "Restoring website data at $webroot"
    Unpack-ZipFiles -sourceFile "$webrootBackupFolder\webroot.zip" -destFolder $webroot

    Write-Output "Finished executing restore for [$Name] website"
}

function Copy-FullFolder([string] $SourcePath, [string] $DestinationPath, [string] $LogFile)
{
    if (-not (Test-Path $SourcePath))
    {
        throw error "$SourcePath path does not exist"
    }

    if (-not (Test-Path $DestinationPath))
    {
        New-Item -ItemType Directory -Path $DestinationPath
    }
    $robocopyOptions = @("/MIR", "/MT", "/FFT", "/W:5", "/R:3", "/NDL", "/NFL")
    #Bug 3822095:Servicing - in HA env the aos backup step failed with filename or extension too long error message

    $cmdArgs = @($robocopyOptions, "$SourcePath", "$DestinationPath")
    & Robocopy.exe @cmdArgs > $LogFile
    $roboCopyExitCode = $lastExitCode

    # Any value greater than 8 or minus value indicates that there was at least one failure during the copy operation..
    # 8 Several files did not copy.
    if (($roboCopyExitCode -ge 8) -or ($roboCopyExitCode -lt 0))
    {
        throw error "Robocopy.exe exited with code $roboCopyExitCode"
    }

    return $roboCopyExitCode
}

function Copy-SymbolicLinks([string] $SourcePath, [string] $DestinationPath, [switch] $Move = $false)
{
    if (-not (Test-Path $SourcePath))
    {
        throw error "$SourcePath path does not exist"
    }

    $filesToCopy = @{ } # Hashtable for each folder and files inside that folder to copy
    $foldersToCopy = @() # List of folders to copy

    # Parse existing files into folders and files that needs to be copied.
    Get-ChildItem -Recurse $SourcePath | Where-Object { $_.LinkType -eq "SymbolicLink" } | ForEach-Object {
        $dir = Split-Path $_.FullName -Parent
        $fileName = $_.Name


        if ($_.PSIsContainer)
        {
            $foldersToCopy += $_.FullName
        }
        else
        {
            if ($filesToCopy.ContainsKey($dir))
            {
                $fileList = $filesToCopy.Get_Item($dir)
                $fileList += $fileName
                $filesToCopy.Set_Item($dir, $fileList)
            }
            else
            {
                $fileList = @()
                $fileList += $fileName
                $filesToCopy.Add($dir, $fileList)
            }
        }
    }

    # Robocopy files, with each iteration going through a new directory
    $filesToCopy.GetEnumerator() | ForEach-Object {
        $source = $_.Key
        $files = $_.Value
        $relative = Get-RelativePath -ChildPath $source -ParentPath $SourcePath
        $destination = Join-Path $DestinationPath $relative

        if (-not (Test-Path $destination))
        {
            New-Item -ItemType Directory -Path $destination
        }
        $robocopyOptions = @("/SL")
        #Bug 3822095:Servicing - in HA env the aos backup step failed with filename or extension too long error message
        foreach ($file in $files)
        {
            $cmdArgs = @($robocopyOptions, "$source", "$destination", @($file))
            & Robocopy.exe @cmdArgs >$null
        }
    }

    # Copy symbolic link folders, since robocopy does not support them
    $foldersToCopy | ForEach-Object {
        $source = $_
        $relative = Get-RelativePath -ChildPath $source -ParentPath $SourcePath
        $destination = Join-Path $DestinationPath $relative
        xcopy.exe /b /i $source $destination >$null
    }

    if ($Move)
    {
        $filesToCopy.GetEnumerator() | ForEach-Object {
            $folder = $_.Key
            $_.Value | ForEach-Object {
                $file = $_
                $fullPath = Join-Path $folder $file
                Remove-Item -Force $fullPath
            }
        }

        $foldersToCopy | ForEach-Object {
            [System.IO.Directory]::Delete($_, $true)
        }
    }
}

function Get-RelativePath([string] $ChildPath, [string] $ParentPath)
{
    # Parent path must be resolved to literal
    $parentLiteralPath = Resolve-Path $ParentPath
    $childLiteralPath = Resolve-Path $ChildPath

    $parentMatch = $parentLiteralPath -replace "\\", "\\"
    if ($childLiteralPath -match "^$parentMatch(.+)$")
    {
        return $Matches[1]
    }
    else
    {
        # ChildPath is not a child of ParentPath, return empty string
        return ''
    }
}

# function to update the connection string
function Update-AOSConnectionString ([hashtable] $AxConnectionString, [string] $webConfigPath)
{
    [System.Xml.XmlDocument] $webConfig = new-object System.Xml.XmlDocument
    $webConfig.Load($webConfigPath)
    $xpath = "/configuration/appSettings/add[@key='DataAccess.DbServer' or @key='DataAccess.Database']"
    $nodes = $webConfig.SelectNodes($xpath)

    foreach ($node in $nodes)
    {
        if ($node.Key -eq 'DataAccess.DbServer')
        {
            If ($node.Value -ne $AxConnectionString['AxServerName'])
            {
                $node.value = $AxConnectionString['AxServerName']
                Write-Output "Updated value for $($node.Key) as $($AxConnectionString.AxServerName)"
            }
            else
            {
                Write-Output "Updating value for $($node.Key) is not required. Skipping this update."
            }
        }
    
        if ($node.Key -eq 'DataAccess.Database')
        {
            If ($node.Value -ne $AxConnectionString['AxDatabaseName'])
            {
                $node.value = $AxConnectionString['AxDatabaseName']
                Write-Output "Updated value for $($node.Key) as $($AxConnectionString.AxDatabaseName)"
            }
            else
            {
                Write-Output "Updating value for $($node.Key) is not required. Skipping this update."
            }
        }
    }
  
    $webConfig.Save($webConfigPath)
}

function KillWatchdogProcess
{
    $ServiceName = $serviceName = "watchdogservice"
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue)
    {
        # Ensure the service in running or stopped state before attempting to stop.
        $timeout = new-timespan -Minutes 5
        $serviceProcessStarting = $true;
        $sw = [diagnostics.stopwatch]::StartNew()
        while ($sw.elapsed -lt $timeout -and $serviceProcessStarting)
        {
            if ((Get-Service $ServiceName | where status -ne 'Running' ) -and (Get-Service $ServiceName | where status -ne 'Stopped' ))
            {
                start-sleep -seconds 60 
            }
            else
            {
                $serviceProcessStarting = $false;
            }
        }
        Write-ServicingLog "Current state of the process: $serviceProcessStarting"
        if ($serviceProcessStarting)
        {
            throw "Unable to execute the $ServiceName shutdown script because the  process is not in a state where operation can be performed."
        }

        # Stop and disable the service
        Set-Service $ServiceName -startupType Disabled
        Write-ServicingLog "Stopping the service: $ServiceName"
        Stop-Service $ServiceName -Force

        # Kill any process related to the watchdog 
        $processName = "Microsoft.Dynamics365.Watchdog.Service"
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
        If ($process)
        {
            Write-ServicingLog "Found running processes for $processName. Killing processes forcibly"
            $process | Stop-Process -Force
        }
        else
        {
            Write-ServicingLog "No processes found running for $processName. Skipping the killing of process."
        }

        $svc = Get-Service $ServiceName
        $runningProcess = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($svc.Status -eq "Stopped" -and !$runningProcess)
        {
            Write-ServicingLog "$ServiceName stopped. No process found running for $processName"
        } 
        else 
        {
            $status = $svc.Status
            $msg = "Unable to stop service $ServiceName. Current Status: $status"
            if ($runningProcess)
            {
                $msg = "Unable to stop service $ServiceName or process $processName. Current Status of service: $status; running processes: $processName"
            }
            throw $msg
        }       
    }
    else
    {
        Write-ServicingLog "$ServiceName not installed. Exiting."
    }
}

# Get application release from aos
# This funtion is moved from AOSEnvironmentUtilities.psm1 for consumption by retail scripts
function Get-ApplicationReleaseFromAOS([Parameter(Mandatory = $false)] $webroot)
{
    if ($webroot -eq $null)
    {
        $webroot = Get-AosWebSitePhysicalPath
    }


    #must use job or process to load the production information provider dll or it'll lock it self
    #in memory copy is not usable as this dll have some special hard coded reference dll which won't resolve when loaded in memory.
    $job = Start-Job -ScriptBlock {
        param($webrootBlock)
        $VersionDLLPath = Join-Path $webrootBlock 'bin\Microsoft.Dynamics.BusinessPlatform.ProductInformation.Provider.dll'
        Add-Type -Path $VersionDLLPath
        $provider = [Microsoft.Dynamics.BusinessPlatform.ProductInformation.Provider.ProductInfoProvider]::get_Provider();
        $version = $provider.get_ApplicationVersion();
        $version
    } -ArgumentList $webroot
    Wait-Job -Job $job | Out-Null
    $version = Receive-Job -Job $job

    if ($((![string]::IsNullOrEmpty($version)) -and ($version -ne '7.0') -and ($version -ne '7.0.0.0')))
    {
        return $version
    }
    else
    {
        return "RTW"
    }
}

<#
.SYNOPSIS
    Ensure copy staging task is not running, otherwise an exception will be thrown in this function
#>
function Disable-CopyStagingTask
{
    $taskName = "DynamicsServicingCopyStaging"
    $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $scheduledTask)
    {
        Write-ServicingLog "No scheduled task '$taskName' detected"
        return
    }

    if ($scheduledTask.State -ne "Disabled")
    {
        $disableTaskScript = {
            Write-ServicingLog "Stopping scheduled task '$taskName'"
            Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop

            Write-ServicingLog "Disabling scheduled task '$taskName'"
            Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop

            $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($scheduledTask -and $scheduledTask.State -ne "Disabled")
            {
                throw "$scheduledTask is $($scheduledTask.State) after disabling"
            }
        }

        Invoke-WithRetry $disableTaskScript
    }
}

<#
.SYNOPSIS
    Ensure copy staging task is not running, otherwise an exception will be thrown in this function
#>
function Assert-CopyStagingTaskNotRunning
{
    $taskName = "DynamicsServicingCopyStaging"
    $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $scheduledTask)
    {
        Write-ServicingLog "No scheduled task '$taskName' detected"
        return
    }

    if ($scheduledTask.State -ne "Disabled")
    {
        throw "Task '$taskName' is in '$($scheduledTask.State)' state! It should have been disabled!"
    }

    Write-ServicingLog "Task '$taskName' is disabled"
}

function Set-CopyStagingWorkingDirectory([string]$taskWorkingDirectory, [string]$taskScriptFilePath)
{
    $deployablePackagePath = (Resolve-Path "$PSScriptRoot/../..").Path

    if (-not (Test-Path $taskWorkingDirectory))
    {
        Write-ServicingLog "Creating directory: $taskWorkingDirectory ."
        New-Item -ItemType Directory -Path $taskWorkingDirectory -ErrorAction Stop
    }

    if (-not (Test-Path $taskScriptFilePath))
    {
        $taskScriptSourcePath = Join-Path $PSScriptRoot "CopyStagingFolderTaskLog.ps1"

        if (-not (Test-Path $taskScriptSourcePath))
        {
            throw "'$taskScriptSourcePath' is not found."
        }
        else
        {
            Write-ServicingLog "Copying '$taskScriptSourcePath' to directory '$taskWorkingDirectory'"
            Copy-Item $taskScriptSourcePath -Destination $taskWorkingDirectory -ErrorAction Stop
        }

        Write-ServicingLog "'$taskScriptFilePath' created!"
    }

    $targetEventSourceDllPath = Join-Path $taskWorkingDirectory "Microsoft.Dynamics.ApplicationPlatform.Development.Instrumentation.dll"
    if (-not (Test-Path $targetEventSourceDllPath))
    {
        $sourceEventSourceDllPath = Join-Path $deployablePackagePath "Microsoft.Dynamics.ApplicationPlatform.Development.Instrumentation.dll"
        Write-ServicingLog "Copying script from '$sourceEventSourceDllPath' to directory '$targetEventSourceDllPath' ."
        Copy-Item $sourceEventSourceDllPath $targetEventSourceDllPath -ErrorAction Stop
    }
}

<#
.SYNOPSIS
    Create copy staging task with disabled state if the task doesn't exist
#>
function Set-CopyStagingTask
{
    $taskName = "DynamicsServicingCopyStaging"
    $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $scheduledTask)
    {
        Write-ServicingLog "Creating scheduled task '$taskName'."
        $CopyStagingFolderTaskTemplate =@'
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
     <Version>1.0.0</Version>
     <Description>Copying aosservice folder to aosservicestaging every day.</Description>
  </RegistrationInfo>
  <Settings>
    <Enabled>false</Enabled>
  </Settings>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2100-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Actions/>
</Task>
'@
        $sourceFolderPath = Get-AosServicePath
        $targetFolderPath = Get-AosServiceStagingPath

        $taskWorkingDirectory = Join-Path $env:SystemDrive "DynamicsServicing"
        $taskScriptFilePath = Join-Path $taskWorkingDirectory "CopyStagingFolderTaskLog.ps1"
        $robocopyLogFile = Join-Path $taskWorkingDirectory "robocopylog.txt"
        Set-CopyStagingWorkingDirectory $taskWorkingDirectory $taskScriptFilePath

        [xml]$taskTemplate = $CopyStagingFolderTaskTemplate
        $taskActions = @(
            @{ Command = "powershell.exe"; Arguments = "-WindowStyle Hidden -ExecutionPolicy bypass -File $taskScriptFilePath " }
            @{ Command = "robocopy.exe"; Arguments = "`"$sourceFolderPath`" `"$targetFolderPath`" /MIR /FFT /W:5 /R:5 /LOG:`"$robocopyLogFile`"" }
            @{ Command = "powershell.exe"; Arguments = "-WindowStyle Hidden -ExecutionPolicy bypass -File $taskScriptFilePath -end" }
        )

        $taskNamespace = [System.Xml.XmlNamespaceManager]::new($taskTemplate.NameTable)
        $taskNamespace.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")
        $actionsNode = $taskTemplate.SelectSingleNode("/t:Task/t:Actions", $taskNamespace)

        foreach($taskAction in $taskActions)
        {
            $execNode = [xml]("<Exec><Command>{0}</Command><Arguments>{1}</Arguments></Exec>" -f $taskAction.Command, $taskAction.Arguments)
            $actionsNode.AppendChild($taskTemplate.ImportNode($execNode.SelectSingleNode("/Exec"), $true))
        }
        $xmlPath = Join-Path $PSScriptRoot "copystagingtask.xml"

        $taskTemplate.OuterXml.Replace("xmlns=`"`"", "") | Out-File $xmlPath

        $scheduleTasksProc = "schtasks.exe"
        $argumentList = "/Create /TN $taskName /RU SYSTEM /XML `"$xmlPath`""

        Write-ServicingLog "Starting $scheduleTasksProc $argumentList"
    
        $proc = Start-Process -FilePath $scheduleTasksProc -ArgumentList $argumentList -NoNewWindow -PassThru -Wait
    
        if ($proc.ExitCode -ne 0)
        {
            throw "Failed to schedule copy staging task. Exit Code: $($proc.ExitCode)"
        }

        Write-ServicingLog "Finished $scheduleTasksProc $argumentList"

    }
    else
    {
        Write-ServicingLog "'$taskName' already exists!"        
    }
}

<#
.SYNOPSIS
    Log the process that locking the given file, and also stop the process if necessary to release the lock.

.PARAMETER fileName
    The full path of the file that is locked by some process

.PARAMETER safeProcessListToClose
    A set of process name that can be safely closed if any process from it is detected locking the file

#>
function Resolve-FileLock([string] $fileName, [System.Collections.Generic.HashSet[string]] $safeProcessListToClose = $null)
{
    if (-not (Locate-FileLockCheckDll))
    {
        return
    }

    Add-Type -LiteralPath $Global:FileLockCheckDll_Path
    $fileName = (Resolve-Path $fileName).Path
    $processList = [FileLockCheck.FileLockCheck]::GetProcessLockingTheFile(@($fileName))

    foreach ($processId in $processList)
    {
        try {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue

            if ($process -ne $null)
            {
                Write-ServicingLog "$($process.Name)[$($process.Id)] is locking $fileName"

                if ($safeProcessListToClose -ne $null -and $safeProcessListToClose.Contains($process.Name))
                {
                    Write-ServicingLog "Stopping process '$($process.Name)' to release the lock on '$fileName'"
                    Stop-Process -Id $processId -Force
                }
            }
        } catch {
            Write-ServicingLog "Error in Resolve-FileLock: $_"
        }
    }
}

<#
.SYNOPSIS
    Get build number of installed AOS
#>
function Get-InstalledPlatformBuild([Parameter(Mandatory=$false)] $webroot)
{
    if (!$webroot) {
       $webroot = Get-AosWebSitePhysicalPath
    }

    #must use job or process to load the production information provider dll or it'll lock it self
    #in memory copy is not usable as this dll have some special hard coded reference dll which won't resolve when loaded in memory.
    $job = Start-Job -ScriptBlock  {
        param($webrootBlock)
        $VersionDLLPath = Join-Path $webrootBlock 'bin\Microsoft.Dynamics.BusinessPlatform.ProductInformation.Provider.dll'
        Add-Type -Path $VersionDLLPath
        $provider = [Microsoft.Dynamics.BusinessPlatform.ProductInformation.Provider.ProductInfoProvider]::get_Provider();
        $version = $provider.get_PlatformBuildVersion();
        $version
    } -ArgumentList $webroot
    Wait-Job -Job $job | Out-Null
    $version = Receive-Job -Job $job
   
    $build = [System.Version]::new()
    $releaseBuild
    if([System.Version]::TryParse($Version, [ref]$build))
    {
        $releaseBuild = $build.Build
    }
    else
    {
        #default to 0 from 7.0.0.0 
        $releaseBuild = 0
    }   

    return  $releaseBuild
}

<#
.SYNOPSIS
    Analyze the ErrorRecord object and proceed with further actions if necessary.
    Currently, it only detect file lock violation of IOException.
#>
function Resolve-ErrorRecord([System.Management.Automation.ErrorRecord] $errorRecord)
{
    try
    {
        $ex = $errorRecord.Exception
        $level = 0
        $maxLevelOfInnerException = 10

        while ($ex -ne $null -and $level -lt $maxLevelOfInnerException)
        {    
            if ($ex -is [System.IO.IOException])
            {
                $win32ErrorCode = $ex.HResult -band 0xffff
                # https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
                # ERROR_LOCK_VIOLATION is 0x20
                if ($win32ErrorCode -eq 0x20)
                {
                    # Extract the file name from the message
                    if ($ex.Message -match "The process cannot access the file '(?<file>.+)'")
                    {
                        $fileName = $Matches['file']
                        Write-ServicingLog "Trying to resolve the file lock issue for '$fileName'"
                        Resolve-FileLock $fileName
                    }
                }
                else
                {
                    $win32Error = new-object System.ComponentModel.Win32Exception($win32ErrorCode)
                    Write-ServicingLog "IOException detected: [$win32ErrorCode] $win32Error.Message"
                }
                break;
            }

            $ex = $ex.InnerException
            $level += 1
        }
    } catch {
        Write-ServicingLog "Failed to resolve errorRecord: $_"
    }
}

<#
.SYNOPSIS
    Write output if PITR required or not.

.PARAMETER Message
    PITR required flag.
#>
function Write-IsPITRRequiredDuringRollback([string]$PitrRequired)
{
  [hashtable]$returnResult = @{}
  $returnResult.AXDBPITRRequiredDuringRollback =[string]$PitrRequired
  $Object = New-Object PSObject -Property @{ RunbookScriptResult = $returnResult }
  Write-Output $Object
}

Export-ModuleMember -Function Set-ServicingLog
Export-ModuleMember -Function Get-ServicingLog
Export-ModuleMember -Function Write-ServicingLog
Export-ModuleMember -Function Invoke-WithRetry
Export-ModuleMember -Function Test-IsRunningAsAdministrator
Export-ModuleMember -Function Stop-ServiceAndDisableStartup
Export-ModuleMember -Function Backup-WebSite
Export-ModuleMember -Function Create-ZipFiles
Export-ModuleMember -Function Get-AosAppPoolName
Export-ModuleMember -Function Get-ProductConfigurationAppPoolName
Export-ModuleMember -Function Get-AosWebSiteName
Export-ModuleMember -Function Get-AosWebSitePhysicalPath
Export-ModuleMember -Function Get-WebSitePhysicalPath
Export-ModuleMember -Function Restore-WebSite
Export-ModuleMember -Function Unpack-ZipFiles
Export-ModuleMember -Function Copy-SymbolicLinks
Export-ModuleMember -Function Copy-FullFolder
Export-ModuleMember -Function Get-RelativePath
Export-ModuleMember -Function Get-AosServicePath
Export-ModuleMember -Function Get-AosServiceStagingPath
Export-ModuleMember -Function Get-AosServiceBackupPath
Export-ModuleMember -Function Create-ZipFiles-FromFileList
Export-ModuleMember -Function KillProcessLockingFolder
Export-ModuleMember -Function KillAllOtherUserSession
Export-ModuleMember -Function Update-AOSConnectionString
Export-ModuleMember -Function KillWatchdogProcess
Export-ModuleMember -Function Get-ApplicationReleaseFromAOS
Export-ModuleMember -Function Initialize-ScriptProgress
Export-ModuleMember -Function Add-ScriptProgress
Export-ModuleMember -Function Test-ScriptProgress
Export-ModuleMember -Function Copy-ScriptProgressFile
Export-ModuleMember -Function Get-ScriptProgress
Export-ModuleMember -Function Get-RunbookId
Export-ModuleMember -Function Get-PackageRoot
Export-ModuleMember -Function Assert-CopyStagingTaskNotRunning
Export-ModuleMember -Function Disable-CopyStagingTask
Export-ModuleMember -Function Set-CopyStagingTask
Export-ModuleMember -Function Resolve-FileLock
Export-ModuleMember -Function Resolve-ErrorRecord
Export-ModuleMember -Function EventWrite-RunbookScriptTrace
Export-ModuleMember -Function Write-IsPITRRequiredDuringRollback
Export-ModuleMember -Function Reset-IIS
Export-ModuleMember -Function Get-IsIISHealthy
Export-ModuleMember -Function Update-EnableRestartForSiteAfterIISResetOrReboot
Export-ModuleMember -Function Update-EnableRestartForAppPoolAfterIISResetOrReboot
Export-ModuleMember -Function Update-DisableRestartForSiteAfterIISResetOrReboot
Export-ModuleMember -Function Update-DisableRestartForAppPoolAfterIISResetOrReboot
Export-ModuleMember -Function Get-InstalledPlatformBuild


# SIG # Begin signature block
# MIIjnwYJKoZIhvcNAQcCoIIjkDCCI4wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpbvFPoZps0iMF
# SoeN9nDxIWdL0gc7LkD4R/SlPUrms6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVdDCCFXACAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgzyMX5cgA
# HNTgR2P7Y5aeTADBdMv4l2JfXii3VWVP9VwwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAf37sDKfrrsjfM4lg6WdATKph0P+pJvTgQJx4XO4EP
# In+JEzzSZBVxQQBe6uwFGN38fgGwQ7lvxYJb4R90lQ7S5ABIRCLukbe/NFWSMwJz
# g0CwOUUqjpkGtinCafDG5U3HzVcmedB0pcK8dhLKrPyFK5o3V1TDv2QkIbBDQrjl
# EvVumQGQ9NfIGP4jSolA5LvdWhIa8GkVhsMm0jazXTVO+KQN8aJKHhNIkEnS2444
# aLM60FMnhhh+ZHIO4bLtc+UAtL5zW0T1vPpp81vaeP37svBrGoVZk1JzOlwtW0jf
# iMjFQmFzD5v8eHVHEY82BnZUsY+uu816BicfWhr7/sFaoYIS/jCCEvoGCisGAQQB
# gjcDAwExghLqMIIS5gYJKoZIhvcNAQcCoIIS1zCCEtMCAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIP0tacEogX4o7WlWUyjdumVBIvOi/F5tCKelOq1u
# 7LeBAgZhgwt70u4YEzIwMjExMTExMDMxMzE1LjA3MVowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2Wggg5NMIIE+TCCA+GgAwIBAgITMwAAAUGvf1KXXPLc
# RQAAAAABQTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMDEwMTUxNzI4MjdaFw0yMjAxMTIxNzI4MjdaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8irLqL28
# dal+PJUmUJOwvYn/sOCEzQzZyj94XbFPtRhDhPjagvvKOv1GgMoOuXvkpM3uM5E6
# 7vyOCPxqhTAzq7Ak3zkEXXBv7JoM8Xm0x5UcnAkpUiEo0eycRl6bnYIB3KlZW3uz
# 4Jc2v2FV0KCGkLrvqfKP8V/i2hVyN854OejWpx8wGUazM4CYUVowcgEDc76OY+Xa
# 4W27DCZJm2f9ol4BjSL+b2L/T8n/LEGknaUxwSQTN1LQCt+uBDCASd6VQR5CLLJV
# t6MBL0W1NlaWxEAJwlIdyBnS1ihLvRg1jc/KUZe0sRFdD3fhKrjPac3hoy007Fvr
# 6Go0WJ4pr2rJdQIDAQABo4IBGzCCARcwHQYDVR0OBBYEFC0oPyxuLpD9RXBr9c8N
# O0EFEsbEMB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRP
# ME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEww
# SgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAFJ63yJ92ChqCgpexD48
# okviGuC4ikNsvmwlCSet1sFpvJEzLJB8cTF4z4qQTz8AsQtcew6mAVmQCYDu9f5e
# e11xXj1LwHYsZGnSs/OfRul1VKmY51OQpqvK5O/Ct4fs0Iblzo8eyOLJygTk97aX
# VA4Uzq8GblL7LQ5XiwAY446MOALnNXFo/Kq9tvzipwY1YcRn/nlMQ+b92OiLLmHV
# Mi2wAUORiKFvaAfYWjhQd+2qHLMsdpNluwBbWe7FF5ABsDo0HROMWyCgxdLQ3vqr
# 3DMSH3ZWKiirFsvWJmchfZPGRObwqszvSXPFmPBZ9o+er+4UoLV+50GWnnQky7HV
# gLkwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNy
# b3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEy
# MTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwT
# l/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4J
# E458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhg
# RvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchoh
# iq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajy
# eioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwB
# BU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVj
# OlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsG
# A1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJc
# YmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9z
# b2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
# LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0
# MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYx
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0
# bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMA
# dABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCY
# P4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1r
# VFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3
# fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2
# /QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFj
# nXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjgg
# tSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7
# cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwms
# ObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAv
# VCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGv
# WbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA1
# 2u8JJxzVs341Hgi62jbb01+P3nSISRKhggLXMIICQAIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAKrlvym1CquIoQcrzncL
# vkD1WpUDoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDlNsP2MCIYDzIwMjExMTExMDYxOTM0WhgPMjAyMTExMTIw
# NjE5MzRaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOU2w/YCAQAwCgIBAAICFBEC
# Af8wBwIBAAICEXgwCgIFAOU4FXYCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQAjWMZxEeWbqB9BAaGXSIoDr9wV7xtptZmW8hCwiOZp/vPpSQ+TyKP3UFMC9/N6
# l+DJAIvq96QLBsn9hpl+qud6aDgi1Sx2RxN/iWK1yYMTwUcwxJ2qjFgPTBHzCl/G
# GqJp7yl/IpQ4RiUEJ/AewQCeLU2Lq2mCgKJyH7RG+LLWsjGCAw0wggMJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABQa9/Updc8txFAAAA
# AAFBMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIDe9nlM/vSgLNpt5A6aRhDGTDgaLsxw0CnVWzdR3
# XTZEMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgUT8BPIzqc3SecHRPLKBt
# W0vOOnT+78haWo+XcxVerd4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAUGvf1KXXPLcRQAAAAABQTAiBCASf5z2RogRw9kzaPb22MOm
# 4jPdwgnIQDbe07uARxK0ADANBgkqhkiG9w0BAQsFAASCAQCKMY2izR8IDnVji1PL
# Fck6LcNMSpu9dkG5zGbvo+uUP8pbEgrRj5KfT3QD7YR5EHKzh+cLT98nBSM0lh3L
# E3HFH1CFllZg97jT9dgc+lSxPMtU71+pTaAiWPvoLmUd/D5EbJ6eTwgf+sM92ITD
# 5ghv53ghTUmXD2fHMmbLorilPazqZ4y2mLKnJ1C77lOu7EzkAeCR6CZAFJ1rhH5p
# WGrLggRjRAuS2Tm11zWfsue2iGCCmoAy+RGOe1nbueNlxSwHc51RvX4PrdMAhp4Z
# ABgi7uOGQLY7zPKnyqR0Hn+h9tGPOErUesVYCCXDwxsH1edFpZHyWHXeWTtJzVb8
# WIbz
# SIG # End signature block
