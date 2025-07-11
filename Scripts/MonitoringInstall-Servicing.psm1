<#
.SYNOPSIS
    Functions to manage the Monitoring Agent during servicing.

.DESCRIPTION
    Contains a set of functions used by the Dynamics 365 for Finance and Operations
    Enterprise Edition servicing process to interact with the Geneva Monitoring Agent.

.NOTES
    Requires PowerShell 3.0 or later.

    Configure Write-Message by calling Set-WriteMessageLogFilePath to set a
    file to send output to.

    Copyright © 2019 Microsoft. All rights reserved.
#>

# Module level variables to control default behavior of Write-Message.
[string]$Script:WriteMessageLogFilePath = $null

<#
.SYNOPSIS
    Set module level variable to control default behavior of Write-Message.
    Set to the full path of the file to append output to (default is null).
#>
function Set-WriteMessageLogFilePath
{
    [CmdletBinding()]
    Param([string]$Path)

    $Script:WriteMessageLogFilePath = $Path
}

<#
.SYNOPSIS
    Write messages to log file and/or output.
#>
function Write-Message
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $false, ValueFromPipeline = $true)][string[]]$Message,
        [switch]$Vrb,
        [string]$LogFilePath = $Script:WriteMessageLogFilePath)

    Process
    {
        if ($LogFilePath)
        {
            $Message | ForEach-Object { "$([DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")): $($_)" | Out-File -FilePath $LogFilePath -Append }
        }

        # Verbose messages only goes to log file.
        if (!$Vrb)
        {
            $Message | Write-Output
        }
    }
}

<#
.SYNOPSIS
    Returns the registry path for the MonitoringInstall settings.
#>
function Get-MonitoringInstallRegistryPath
{
    return "HKLM:\SOFTWARE\Microsoft\Dynamics\AX\Diagnostics\MonitoringInstall"
}

<#
.SYNOPSIS
    Returns the scheduled task path for the MonitoringInstall tasks.
#>
function Get-MonitoringInstallTaskPath
{
    # Task path must begin and end with "\" for Get-ScheduledTask to work.
    return "\Microsoft\Dynamics\AX\Diagnostics\"
}

<#
.SYNOPSIS
    Read the Monitoring installation path from registry.
#>
function Get-MonitoringInstallPath()
{
    $RegistryPath = Get-MonitoringInstallRegistryPath
    $InstallPathKey = "InstallPath"
    $InstallPath = $null

    if (Test-Path -LiteralPath $RegistryPath -ErrorAction SilentlyContinue)
    {
        $RegistryKey = Get-Item -LiteralPath $RegistryPath -ErrorAction SilentlyContinue
        if ($RegistryKey)
        {
            $InstallPath = $RegistryKey.GetValue($InstallPathKey)
            if (!$InstallPath)
            {
                Write-Message "Warning: Could not read MonitoringInstall registry key $($InstallPathKey) from: $($RegistryPath)" -Vrb
            }
        }
        else
        {
            Write-Message "Warning: Could not read MonitoringInstall registry keys from: $($RegistryPath)" -Vrb
        }
    }
    else
    {
        Write-Message "Warning: Could not find MonitoringInstall registry path: $($RegistryPath)" -Vrb
    }

    return $InstallPath
}

<#
.SYNOPSIS
    Get the default Monitoring installation path.
#>
function Get-MonitoringInstallPathDefault()
{
    if ($env:SERVICEDRIVE)
    {
        $InstallPath = Join-Path -Path "$($env:SERVICEDRIVE)" -ChildPath "Monitoring"
    }
    else
    {
        $InstallPath = Join-Path -Path "$($env:SystemDrive)" -ChildPath "Monitoring"
    }

    return $InstallPath
}

<#
.SYNOPSIS
    Read the Monitoring manifest path from registry.
#>
function Get-MonitoringManifestPath()
{
    $RegistryPath = Get-MonitoringInstallRegistryPath
    $ManifestPathKey = "ManifestPath"
    $ManifestPath = $null

    if (Test-Path -LiteralPath $RegistryPath -ErrorAction SilentlyContinue)
    {
        $RegistryKey = Get-Item -LiteralPath $RegistryPath -ErrorAction SilentlyContinue
        if ($RegistryKey)
        {
            $ManifestPath = $RegistryKey.GetValue($ManifestPathKey)
            if (!$ManifestPath)
            {
                Write-Message "Warning: Could not read MonitoringInstall registry key $($ManifestPathKey) from: $($RegistryPath)" -Vrb
            }
        }
        else
        {
            Write-Message "Warning: Could not read MonitoringInstall registry key: $($RegistryPath)" -Vrb
        }
    }
    else
    {
        Write-Message "Warning: Could not find MonitoringInstall registry path: $($RegistryPath)" -Vrb
    }

    return $ManifestPath
}

<#
.SYNOPSIS
    Get the default Monitoring manifest path.
#>
function Get-MonitoringManifestPathDefault()
{
    $InstallPath = Get-MonitoringInstallPath
    if (!$InstallPath)
    {
        $InstallPath = Get-MonitoringInstallPathDefault
    }

    $ManifestPath = Join-Path -Path $InstallPath -ChildPath "Instrumentation"

    return $ManifestPath
}

<#
.SYNOPSIS
    Create task for MonitoringInstall.exe action and run as SYSTEM.
#>
function Invoke-MonitoringInstallAsSystem([string]$MonitoringInstallFilePath, [string]$LogPath, [string]$Action, [int]$MaxWaitSec = 300, [int]$MaxLogLines = 100, [switch]$UseExistingTask)
{
    try
    {
        $TaskPath = Get-MonitoringInstallTaskPath
        $TaskName = "MonitoringInstall-$($Action)"
        $MonitoringInstallPath = Split-Path -Path $MonitoringInstallFilePath -Parent

        if ($LogPath)
        {
            if (!(Test-Path -Path $LogPath))
            {
                New-Item -Path $LogPath -ItemType Directory | Out-Null
            }

            $LogFilePath = Join-Path -Path $LogPath -ChildPath "$($TaskName)_$([DateTime]::UtcNow.ToString("yyyyMMddHHmmss")).log"
        }
        else
        {
            # Default to using the log file path in the MonitoringInstall folder.
            $LogFilePath = Join-Path -Path $MonitoringInstallPath -ChildPath "$($TaskName).log"
        }

        Write-Message "Getting the $($TaskName) task..." -Vrb
        $ExistingTask = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($ExistingTask)
        {
            if ($UseExistingTask)
            {
                Write-Message "Using existing $($TaskName) task found (State: $($ExistingTask.State))." -Vrb
                $Task = $ExistingTask
            }
            else
            {
                Write-Message "Existing $($TaskName) task found, but it will be replaced (State: $($ExistingTask.State))." -Vrb
            }
        }

        if (!$Task)
        {
            Write-Message "Creating $($TaskName) task to run as SYSTEM." -Vrb
            $TaskAction = New-ScheduledTaskAction -Execute $MonitoringInstallFilePath -Argument "/$($Action) /id:SingleAgent /log:$LogFilePath" -WorkingDirectory $MonitoringInstallPath
            $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds $MaxWaitSec)
            $Task = Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -User "SYSTEM" -Action $TaskAction -Settings $TaskSettings -Force
        }

        Write-Message "Starting the $($TaskName) task..." -Vrb
        $Task | Start-ScheduledTask
        $ScheduledTask = $Task | Get-ScheduledTask
        Write-Message "Scheduled task started (State: $($ScheduledTask.State))." -Vrb

        Write-Message "Waiting up to $($MaxWaitSec) seconds for the $($TaskName) task to complete..." -Vrb
        [int]$WaitedSec = 0
        while ($ScheduledTask.State -ine "Ready" -and $WaitedSec -lt $MaxWaitSec)
        {
            Start-Sleep -Seconds 1
            $WaitedSec += 1
            $ScheduledTask = $Task | Get-ScheduledTask
        }

        # Check if task completed.
        if ($ScheduledTask.State -ine "Ready")
        {
            $ErrorMessage = "Exceeded timeout after waiting $($WaitedSec) seconds for the $($TaskName) task to complete (State: $($ScheduledTask.State))."
            Write-Message "Error: $($ErrorMessage)" -Vrb
            throw $ErrorMessage
        }
        else
        {
            Write-Message "Completed the $($TaskName) task after waiting $($WaitedSec) seconds (State: $($ScheduledTask.State))." -Vrb
            $TaskInfo = $ScheduledTask | Get-ScheduledTaskInfo
            if ($TaskInfo)
            {
                # Note: Currently the MonitoringInstall exit code cannot be used to determine success or failure.
                Write-Message "The exit code of the $($TaskName) task run at $($TaskInfo.LastRunTime.ToString("u")) is: $($TaskInfo.LastTaskResult)." -Vrb
            }
            else
            {
                Write-Message "Warning: No task run information could be found from the $($TaskName) task." -Vrb
            }
        }

        # Check log content.
        if (Test-Path -Path $LogFilePath -ErrorAction SilentlyContinue)
        {
            $LogContent = Get-Content -Path $LogFilePath -Tail $MaxLogLines
            if ($LogContent)
            {
                Write-Message "The MonitoringInstall $($Action) action log file exists at: $($LogFilePath)" -Vrb
                Write-Message "Contents of log (Last $($MaxLogLines)):" -Vrb
                foreach ($Line in $LogContent)
                {
                    Write-Message $Line -Vrb
                }

                Write-Message "*** End of Log ***" -Vrb
            }
            else
            {
                Write-Message "Warning: The MonitoringInstall $($Action) action did not write any contents to log file at: $($LogFilePath)" -Vrb
            }
        }
        else
        {
            Write-Message "Warning: The MonitoringInstall $($Action) action did not produce any log file at: $($LogFilePath)" -Vrb
        }
    }
    catch
    {
        Write-Message "Error: Failed to run MonitoringInstall $($Action) action: $($_.Message)." -Vrb
        throw
    }
    finally
    {
        # If task was triggered, make sure it is stopped.
        if ($ScheduledTask)
        {
            $ScheduledTask = $ScheduledTask | Get-ScheduledTask

            if ($ScheduledTask -and $ScheduledTask.State -ieq "Running")
            {
                Write-Message "Stopping the $($ScheduledTask.TaskName) task as it is still running." -Vrb
                $ScheduledTask | Stop-ScheduledTask
            }
        }
    }
}

<#
.SYNOPSIS
    Stop Monitoring Agent ETW sessions and processes.
#>
function Stop-MonitoringAgent([int]$MaxWaitSec = 300, [string]$LogPath, [switch]$SkipIfNotInstalled)
{
    $InstallPath = Get-MonitoringInstallPath
    if (!$InstallPath)
    {
        # Return without action if Monitoring Install path was not found in registry and skip switch specified.
        if ($SkipIfNotInstalled)
        {
            Write-Message "No Monitoring Install path found in registry. No attempt to stop the Monitoring Agent will be made." -Vrb
            return
        }
        else
        {
            $InstallPath = Get-MonitoringInstallPathDefault
            Write-Message "Warning: No Monitoring Install path found in registry. Using default: $($InstallPath)." -Vrb
        }
    }

    $MonitoringInstallPath = Join-Path -Path $InstallPath -ChildPath "MonitoringInstall"
    if (!(Test-Path -Path $MonitoringInstallPath -ErrorAction SilentlyContinue))
    {
        throw "No MonitoringInstall folder found at: $($MonitoringInstallPath)"
    }

    $MonitoringInstallFilePath = Join-Path -Path $MonitoringInstallPath -ChildPath "MonitoringInstall.exe"
    if (!(Test-Path -Path $MonitoringInstallFilePath -ErrorAction SilentlyContinue))
    {
        throw "No MonitoringInstall.exe file found at: $($MonitoringInstallFilePath)"
    }

    # Stop the Monitoring Install task if it is running.
    # This must be done before attempting to stop Monitoring Agent as it could otherwise
    # be triggering a start of Monitoring Agent after attempting to stop it.
    try
    {
        Write-Message "Stopping Monitoring Install task..."
        Stop-MonitoringInstallTask -MaxWaitSec $MaxWaitSec
    }
    catch
    {
        # This may not be a problem that requires the update process to stop.
        Write-Message "Warning: Failed to stop the MonitoringInstall task: $($_.Message)."
    }

    # Stop Monitoring ETW Sessions as SYSTEM.
    try
    {
        Write-Message "Stopping Monitoring ETW Sessions..."
        Invoke-MonitoringInstallAsSystem -MonitoringInstallFilePath $MonitoringInstallFilePath -Action "StopSessions" -LogPath $LogPath
    }
    catch
    {
        # This may not be a problem that requires the update process to stop.
        Write-Message "Warning: MonitoringInstall failed to stop Monitoring ETW Sessions: $($_.Message)."
    }

    # Stop Monitoring Agent processes as SYSTEM.
    try
    {
        Write-Message "Stopping Monitoring Agent processes..."

        $StopAgentAction = "StopAgents"

        # Determine if MonitoringInstall.exe has the new and improved StopAgentLauncher action.
        # First released with MonitoringInstall.exe 9.3.1789.0 in January 2019.
        # Note: The old StopAgent doesn't actually stop the MonAgentLauncher process, so the other
        # Monitoring Agent processes will be restarted if it does not forcefully terminate it in time.
        $MonitoringInstallFile = Get-Item -Path $MonitoringInstallFilePath
        if ($MonitoringInstallFile.VersionInfo.FileVersion)
        {
            if ($MonitoringInstallFile.VersionInfo.FileMajorPart -ge 9 -and $MonitoringInstallFile.VersionInfo.FileMinorPart -ge 3 -and $MonitoringInstallFile.VersionInfo.FileBuildPart -ge 1789)
            {
                Write-Message "Using MonitoringInstall.exe $($MonitoringInstallFile.VersionInfo.FileVersion) with StopAgentLauncher action." -Vrb
                $StopAgentAction = "StopAgentLauncher"
            }
            else
            {
                Write-Message "Using MonitoringInstall.exe $($MonitoringInstallFile.VersionInfo.FileVersion) with StopAgents action." -Vrb
            }
        }
        else
        {
            Write-Message "Using MonitoringInstall.exe which has no file version information with StopAgents action." -Vrb
        }

        Invoke-MonitoringInstallAsSystem -MonitoringInstallFilePath $MonitoringInstallFilePath -Action $StopAgentAction -LogPath $LogPath
    }
    catch
    {
        # Not being able to stop the Monitoring Agent processes is a fatal problem.
        Write-Message "Error: MonitoringInstall failed to stop Monitoring Agent processes: $($_.Message)." -Vrb
        throw
    }
    finally
    {
        # Log any running Monitoring Agent processes after stop.
        try
        {
            $Processes = Get-MonitoringAgentProcesses
            if ($Processes.Count -gt 0)
            {
                Write-Message "Found $($Processes.Count) Monitoring Agent processes running after stop:" -Vrb
                foreach ($Process in $Processes)
                {
                    Write-Message "- $($Process.Id): $($Process.Name) started at $($Process.StartTime.Tostring("u"))." -Vrb
                }
            }
            else
            {
                Write-Message "Found no Monitoring Agent processes running after stop." -Vrb
            }
        }
        catch
        {
            Write-Message "Warning: Unable to get Monitoring Agent processes running: ($_)" -Vrb
        }
    }
}

<#
.SYNOPSIS
    Start the task to register ETW events, build configurations, and start the Monitoring Agent.
#>
function Start-MonitoringAgent([int]$MaxWaitSec = 300, [switch]$SkipIfNotInstalled)
{
    $TaskPath = Get-MonitoringInstallTaskPath
    $TaskName = "MonitoringInstall"

    Write-Message "Getting the $($TaskName) task..." -Vrb
    $Task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if (!$Task)
    {
        # Very old installations created the task in the root path.
        Write-Message "Warning: No '$($TaskName)' task found in path '$($TaskPath)'. Looking for task in all paths..." -Vrb
        $Task = Get-ScheduledTask | Where-Object -FilterScript { $_.TaskName -ieq $TaskName } | Select-Object -First 1
    }

    If ($Task)
    {
        Write-Message "The $($TaskName) task was found (State: $($Task.State))." -Vrb
        Write-Message "Starting the $($TaskName) task..." -Vrb
        $Task | Start-ScheduledTask
        $ScheduledTask = $Task | Get-ScheduledTask
        Write-Message "Scheduled task started (State: $($ScheduledTask.State))." -Vrb

        if ($MaxWaitSec -gt 0)
        {
            Write-Message "Waiting up to $($MaxWaitSec) seconds for the $($TaskName) task to complete..." -Vrb

            [int]$WaitedSec = 0
            while ($ScheduledTask.State -ine "Ready" -and $WaitedSec -lt $MaxWaitSec)
            {
                Start-Sleep -Seconds 1
                $WaitedSec += 1
                $ScheduledTask = $Task | Get-ScheduledTask
            }

            # Log any running Monitoring Agent processes after start.
            try
            {
                $Processes = Get-MonitoringAgentProcesses
                if ($Processes.Count -gt 0)
                {
                    Write-Message "Found $($Processes.Count) Monitoring Agent processes running after start:" -Vrb
                    foreach ($Process in $Processes)
                    {
                        Write-Message "- $($Process.Id): $($Process.Name) started at $($Process.StartTime.Tostring("u"))." -Vrb
                    }
                }
                else
                {
                    Write-Message "Found no Monitoring Agent processes running after start." -Vrb
                }
            }
            catch
            {
                Write-Message "Warning: Unable to get Monitoring Agent processes running: ($_)" -Vrb
            }

            # Check if task completed.
            if ($ScheduledTask.State -ine "Ready")
            {
                $ErrorMessage = "Exceeded timeout after waiting $($WaitedSec) seconds for the $($TaskName) task to complete (State: $($ScheduledTask.State))."
                Write-Message "Error: $($ErrorMessage)" -Vrb
                throw $ErrorMessage
            }
            else
            {
                Write-Message "Completed the $($TaskName) task after waiting $($WaitedSec) seconds (State: $($ScheduledTask.State))." -Vrb
                $TaskInfo = $ScheduledTask | Get-ScheduledTaskInfo
                if ($TaskInfo)
                {
                    # Note: Currently the MonitoringInstall exit code cannot be used to determine success or failure.
                    Write-Message "The exit code of the $($TaskName) task run at $($TaskInfo.LastRunTime.ToString("u")) is: $($TaskInfo.LastTaskResult)." -Vrb
                }
                else
                {
                    Write-Message "Warning: No task run information could be found from the $($TaskName) task." -Vrb
                }
            }
        }
        else
        {
            Write-Message "Not waiting for the $($TaskName) task to complete." -Vrb
        }
    }
    else
    {
        # Only throw if Monitoring Install task was not found and no skip switch was specified.
        if ($SkipIfNotInstalled)
        {
            Write-Message "No Monitoring Install task found. No attempt to start the Monitoring Agent will be made." -Vrb
        }
        else
        {
            # Throw if the scheduled task is not found.
            throw "No scheduled task with the name '$($TaskName)' was found. Unable to start Monitoring Agent."
        }
    }
}

<#
.SYNOPSIS
    Stop the Monitoring Install task if it is currently running.
#>
function Stop-MonitoringInstallTask([int]$MaxWaitSec = 300)
{
    $TaskPath = Get-MonitoringInstallTaskPath
    $TaskName = "MonitoringInstall"

    Write-Message "Getting the $($TaskName) task..." -Vrb
    $Task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if (!$Task)
    {
        # Very old installations created the task in the root path.
        Write-Message "Warning: No '$($TaskName)' task found in path '$($TaskPath)'. Looking for task in all paths..." -Vrb
        $Task = Get-ScheduledTask | Where-Object -FilterScript { $_.TaskName -ieq $TaskName } | Select-Object -First 1
    }

    If ($Task)
    {
        Write-Message "The $($TaskName) task was found (State: $($Task.State))." -Vrb
        if ($Task.State -ieq "Running")
        {
            Write-Message "Stopping the running $($TaskName) task..." -Vrb
            $Task | Stop-ScheduledTask
            $ScheduledTask = $Task | Get-ScheduledTask
            Write-Message "Scheduled task stopping (State: $($ScheduledTask.State))." -Vrb

            if ($MaxWaitSec -gt 0)
            {
                Write-Message "Waiting up to $($MaxWaitSec) seconds for the $($TaskName) task to stop..." -Vrb

                [int]$WaitedSec = 0
                while ($ScheduledTask.State -ine "Ready" -and $WaitedSec -lt $MaxWaitSec)
                {
                    Start-Sleep -Seconds 1
                    $WaitedSec += 1
                    $ScheduledTask = $Task | Get-ScheduledTask
                }

                # Check if task completed.
                if ($ScheduledTask.State -ine "Ready")
                {
                    $ErrorMessage = "Exceeded timeout after waiting $($WaitedSec) seconds for the $($TaskName) task to stop (State: $($ScheduledTask.State))."
                    Write-Message "Error: $($ErrorMessage)" -Vrb
                    throw $ErrorMessage
                }
                else
                {
                    Write-Message "Stopped the $($TaskName) task after waiting $($WaitedSec) seconds (State: $($ScheduledTask.State))." -Vrb

                    # Log task info only as additional information. The objective of this function is to stop
                    # the task if it is running, so the result of the task is not important.
                    $TaskInfo = $ScheduledTask | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                    if ($TaskInfo)
                    {
                        Write-Message "The exit code of the $($TaskName) task run at $($TaskInfo.LastRunTime.ToString("u")) is: $($TaskInfo.LastTaskResult)." -Vrb
                    }
                    else
                    {
                        Write-Message "Warning: No task run information could be found from the $($TaskName) task." -Vrb
                    }
                }
            }
            else
            {
                Write-Message "Not waiting for the $($TaskName) task to stop." -Vrb
            }
        }
        else
        {
            Write-Message "Not stopping the $($TaskName) task as it is not running." -Vrb
        }
    }
    else
    {
        # If there is no task found, it is not running, and there is no action required to stop it.
        Write-Message "No Monitoring Install task was found, so there is no task to stop." -Vrb
    }
}

<#
.SYNOPSIS
    Returns the names of the Monitoring Agent processes.
#>
function Get-MonitoringAgentProcessNames
{
    return @("MonAgentLauncher", "MonAgentHost", "MonAgentManager", "MonAgentCore");
}

<#
.SYNOPSIS
    Get all Monitoring Agent processes currently running.
#>
function Get-MonitoringAgentProcesses()
{
    $AgentProcesses = @()

    $AgentProcessNames = Get-MonitoringAgentProcessNames
    foreach ($AgentProcessName in $AgentProcessNames)
    {
        $AgentProcess = Get-Process -Name $AgentProcessName -ErrorAction SilentlyContinue
        if ($AgentProcess)
        {
            if (!$AgentProcess.HasExited)
            {
                $AgentProcesses += $AgentProcess
            }
        }
    }

    return $AgentProcesses
}
# SIG # Begin signature block
# MIIjnwYJKoZIhvcNAQcCoIIjkDCCI4wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAMYUm4B3753drr
# QK+APSrQIgRuDo+vilvZIQcra7KgX6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgYepWAm3v
# P4sbbGx5aN4ZAK7RlqIIRkHjoE64f5+VqzkwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCY7GFfGUkt9b+5aiAe43T3pbHaPSn+oOx9ukQgd/3R
# ZuGwybdpAhJ3LDPIgbXosSj2Z1b5spWzQ0xerO5Q213+8y+M7nYQ+s9xugiVYGT4
# qnm9cVcIzuWD7u95Ssv2lVR7SbKkufRpuMqMn5CPqa0adPXxGiQ/b1Wpj5S1jo1z
# nQpaXW0dJXY3A0lHVr6rvOpp5GRfGd7mwW+8V4jYkb7ui3dgMtfEIfDLZz8dewu6
# KBrm4Jj8CXhX7RA+3bUjeH3JZckckkIt46gMOspcjNyBfk/YfAqGOzxZJO1UvleX
# Rd7AOeVgUVy/WggbqDHAYptgCcB67hc6+F8PJi9Tc7WhoYIS/jCCEvoGCisGAQQB
# gjcDAwExghLqMIIS5gYJKoZIhvcNAQcCoIIS1zCCEtMCAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEILYsI0f1LPMKTLuBJNz7lZHJTHpzg8HF37RkazPQ
# QdA1AgZhgwt70pgYEzIwMjExMTExMDMxMzE0LjEyOVowBIACAfSggdikgdUwgdIx
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
# AQQwLwYJKoZIhvcNAQkEMSIEICvebbOoFjhxR3AngodsRte35IpRzyftrGLHWZ9w
# ymAPMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgUT8BPIzqc3SecHRPLKBt
# W0vOOnT+78haWo+XcxVerd4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAUGvf1KXXPLcRQAAAAABQTAiBCASf5z2RogRw9kzaPb22MOm
# 4jPdwgnIQDbe07uARxK0ADANBgkqhkiG9w0BAQsFAASCAQCWLlZAUb/oY/kFNAc2
# OLOfu8wDZuCsska1YP34Xj6g3lu48PjkWYuT8kMPp3dTdPMwjMy1XR1YpFyRXALQ
# 1Tz6ainbSdwrwQtJv8RKXqdt9bfdmwen/NLmf4xSO9IwfaWyj/58W6/wAcNvOpGh
# +ye9UTuH/HgWjXkBe/9cQAD6WboHiG89UJ/N/YgTgVLO6inBoqjkcb8WYj1LOFbp
# 6ubCNZfNvQaRIuVIX0DwcPfLWt/L1MQf4RLqKkCX7zFarSQ35/3Wmu1Wwg6tTHwu
# tqlH5taycYEaVNeH6t+ke7wcFS4N6NlI79c1iAB/lsnEpFt1lW0hqAX6Pj14+A0R
# pys1
# SIG # End signature block
