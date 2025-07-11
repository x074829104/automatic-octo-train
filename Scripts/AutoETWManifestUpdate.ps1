<#
.SYNOPSIS
    Update the ETW manifest files in the instrumentation folder.

.DESCRIPTION
    The script will stop the Monitoring Agent, unregister the existing ETW manifest files in the
    instrumentation folder, update the ETW manifests in the instrumentation folder, and run the
    MonitoringInstall scheduled task to register the updated ETW manifests and start the Monitoring
    Agent. MonitoringInstall-Servicing.psm1 must exist in the script folder.

    Exit codes:
       0: Success.
       2: Monitoring PowerShell module could not be initialized.
       4: Monitoring Agent could not be stopped.
       8: Monitoring Agent could not be started.
      16: One or more manifest files could not be copied to the backup folder.
      32: One or more manifest files could not be updated.
    1024: Unknown error.

    Copyright © 2019 Microsoft. All rights reserved.
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false, HelpMessage = "The maximum number of seconds to wait for the stop tasks to complete.")]
    [int]$StopTaskMaxWaitSec = 300,
    [Parameter(Mandatory = $false, HelpMessage = "The maximum number of seconds to wait for the start task to complete. Set to 0 to not wait.")]
    [int]$StartTaskMaxWaitSec = 300,
    [Parameter(Mandatory = $false, HelpMessage = "The path to the log directory in which output should be written.")]
    [string]$LogDir
)

# Initialize exit code.
[int]$ExitCode = 0

# Initialize Monitoring module and logging.
[string]$LogPath = $null
try
{
    if ($LogDir)
    {
        # Add log file name.
        $LogPath = Join-Path -Path $LogDir -ChildPath "Monitoring-EtwUpdate_$([DateTime]::UtcNow.ToString("yyyyMMddHHmmss")).log"

        if ([System.IO.Path]::IsPathRooted($LogPath))
        {
            # Ensure that the directory exists.
            $LogParentPath = Split-Path -Path $LogPath -Parent
            if (!(Test-Path -Path $LogParentPath -ErrorAction SilentlyContinue))
            {
                New-Item -Path $LogParentPath -ItemType "Directory" | Out-Null
            }
        }
        else
        {
            # Resolve relative path under current directory.
            $LogPath = Join-Path -Path $PSScriptRoot -ChildPath $LogPath
        }
    }

    $MonitoringModulePath = Join-Path -Path $PSScriptRoot -ChildPath "MonitoringInstall-Servicing.psm1"
    if (!(Test-Path -Path $MonitoringModulePath -ErrorAction SilentlyContinue))
    {
        throw "Monitoring servicing module not found at: $($MonitoringModulePath)"
    }

    # Import Monitoring module.
    Import-Module -Name $MonitoringModulePath

    # For Monitoring Write-Message - Set log file path.
    Set-WriteMessageLogFilePath -Path $LogPath
}
catch
{
    $ExitCode = 2
    $ErrorMessage = "Error initializing Monitoring PowerShell module from '$($MonitoringModulePath)': $($_)"

    # Use Write-Output since Write-Message is defined in module that could not be loaded.
    Write-Output "$([DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")): $($ErrorMessage)"
    Write-Output "$($_.ScriptStackTrace)"
    Write-Output "$($_.Exception)"

    # If a log path was defined, also write error message to it.
    if ($LogPath)
    {
        "$([DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")): $($ErrorMessage)" | Out-File -FilePath $LogPath -Append
        "$($_.ScriptStackTrace)" | Out-File -FilePath $LogPath -Append
        "$($_.Exception)" | Out-File -FilePath $LogPath -Append
        "ETW update script failed with exit code: $($ExitCode)." | Out-File -FilePath $LogPath -Append
    }

    # Use throw to indicate error to AXUpdateInstaller.
    # In case of exceptions, the output is not captured, so only the error message and
    # log file contents will be available for diagnostics.
    throw "$($ErrorMessage) [Log: $($LogPath)]"
}

try
{
    Write-Message "Script to update Monitoring ETW manifest files starting..."
    Write-Message "Command: $(@([Environment]::GetCommandLineArgs()) -join " ")" -Vrb

    # Get the settings file path.
    $SettingsFilePath = Join-Path -Path $PSScriptRoot -ChildPath "Servicing.settings"

    # Check if ETW manifest update is applicable from settings.
    [bool]$UpdateApplicable = $true
    if (Test-Path -Path $SettingsFilePath -ErrorAction SilentlyContinue)
    {
        Write-Message "Reading settings from: $($SettingsFilePath)"
        $SettingsJson = Get-Content -Path $SettingsFilePath -Raw | ConvertFrom-Json

        if ($SettingsJson.ETWManifestUpdate.Skip)
        {
            $UpdateApplicable = $false
            Write-Message "Settings indicate that ETW manifest update is not applicable. Skipping ETW manifest update step."
        }
        else
        {
            Write-Message "Settings indicate that ETW manifest update is applicable."
        }
    }

    # Check if ETW manifest update is applicable from files in ETWManifest folder.
    if ($UpdateApplicable)
    {
        # Script parent path.
        $ScriptParentPath = Split-Path -Parent $PSScriptRoot

        # Source path of updated manifest files.
        $ETWManifestPath = Join-Path -Path $ScriptParentPath -ChildPath "ETWManifest"
        Write-Message "ETW manifest source path: $($ETWManifestPath)"

        if (Test-Path -Path $ETWManifestPath -ErrorAction SilentlyContinue)
        {
            $ETWManifestFiles = @(Get-ChildItem -Path $ETWManifestPath -File)
            if ($ETWManifestFiles.Count -eq 0)
            {
                $UpdateApplicable = $false
                Write-Message "ETW manifest path does not contain any files. Skipping ETW manifest update step."
            }
        }
        else
        {
            $UpdateApplicable = $false
            Write-Message "ETW manifest path does not exist. Skipping ETW manifest update step."
        }
    }

    # If applicable, stop ETW session and agent, backup and update manifest files, register ETW events, and start agent.
    if ($UpdateApplicable)
    {
        # Stop the Monitoring Agent ETW sessions and agent processes.
        try
        {
            Write-Message "Stopping Monitoring Agent..."
            Stop-MonitoringAgent -MaxWaitSec $StopTaskMaxWaitSec -LogPath $LogDir -SkipIfNotInstalled
        }
        catch
        {
            # Set exit code to indicate Monitoring Agent could not be stopped.
            $ExitCode = 4

            # Throw to terminate script.
            throw
        }

        $ErrorMessages = @()

        # Restarting the EventLog service can prevent some locked file issues.
        Write-Message "Restarting EventLog service..." -Vrb
        try
        {
            Restart-Service -Name "EventLog" -Force
        }
        catch
        {
            Write-Message "Warning: Failed to restart EventLog service: $($_)" -Vrb
        }

        # Get Monitoring manifest path.
        $MonManifestPath = Get-MonitoringManifestPath
        if (!$MonManifestPath)
        {
            $MonManifestPath = Get-MonitoringManifestPathDefault
            Write-Message "Warning: No Monitoring Manifest path found in registry. Using default: $($MonManifestPath)" -Vrb
        }

        Write-Message "Monitoring manifest path: $($MonManifestPath)"

        if (!(Test-Path -Path $MonManifestPath -ErrorAction SilentlyContinue))
        {
            Write-Message "Monitoring manifest path was not found. Creating new directory: $($MonManifestPath)" -Vrb
            New-Item -ItemType Directory -Path $MonManifestPath | Out-Null
        }

        # Set backup path. If the RunbookBackupFolder variable is not set, use ManualETWManifestBackup folder.
        $BackupFolder = $RunbookBackupFolder
        if (!$BackupFolder)
        {
            $BackupFolder = Join-Path -Path $PSScriptRoot -ChildPath "ManualETWManifestBackup"
        }

        if (!(Test-Path -Path $BackupFolder -ErrorAction SilentlyContinue))
        {
            Write-Message "Backup path was not found. Creating new directory: $($BackupFolder)" -Vrb
            New-Item -ItemType Directory -Path $BackupFolder | Out-Null
        }

        # Backup existing files from Monitoring manifest folder prior to update (no subfolders).
        $BackupFiles = @(Get-ChildItem -Path $MonManifestPath -File)
        $BackupErrors = @()
        Write-Message "Backing up $($BackupFiles.Count) files from Monitoring manifest folder..."
        foreach ($File in $BackupFiles)
        {
            $DestinationFilePath = Join-Path -Path $BackupFolder -ChildPath $($File.Name)

            # Only copy file to backup folder if it does not already exist or is zero bytes.
            # In case of resume/retries, the backup may already exist and should not be overwritten.
            if ((Test-Path -Path $DestinationFilePath) -and (Get-Item -Path $DestinationFilePath).Length -gt 0)
            {
                Write-Message "- [Already in backup] $($File.Name)" -Vrb
            }
            else
            {
                Write-Message "- [Adding to backup] $($File.Name)" -Vrb

                [int]$Attempt = 1
                [int]$MaxAttempts = 3
                while ($Attempt -le $MaxAttempts)
                {
                    try
                    {
                        Copy-Item -Path $($File.FullName) -Destination $DestinationFilePath -Force
                    }
                    catch
                    {
                        if ($Attempt -lt $MaxAttempts)
                        {
                            Write-Message "- [Warning - $($Attempt)]: Failed to backup $($File.Name): $($_.Exception.Message)." -Vrb
                            Start-Sleep -Second 1
                        }
                        else
                        {
                            Write-Message "- [Error]: Failed all attempts to backup $($File.FullName): $($_.Exception.Message)." -Vrb
                            $BackupErrors += $File
                        }
                    }

                    $Attempt++
                }
            }
        }

        if ($BackupErrors.Count -gt 0)
        {
            Write-Message "Error: Failed to backup $($BackupErrors.Count) files to backup folder."
            $ErrorMessages += "Failed to backup $($BackupErrors.Count) files to backup folder."
            $ExitCode = $ExitCode -bor 32
        }
        else
        {
            Write-Message "Manifest files were all copied to backup at: $($BackupFolder)"
        }

        # Update Monitoring manifest folder with new files from ETWManifest folder (no subfolders).
        $UpdateFiles = @(Get-ChildItem -Path $ETWManifestPath -File)
        $UpdateErrors = @()
        Write-Message "Deploying $($UpdateFiles.Count) files to Monitoring manifest folder..."
        foreach ($File in $UpdateFiles)
        {
            $DestinationFilePath = Join-Path -Path $MonManifestPath -ChildPath $($File.Name)

            [int]$Attempt = 1
            [int]$MaxAttempts = 3
            while ($Attempt -le $MaxAttempts)
            {
                try
                {
                    if (Test-Path -Path $DestinationFilePath -ErrorAction SilentlyContinue)
                    {
                        Write-Message "- [Updating] $($File.Name)" -Vrb
                        Copy-Item -Path $($File.FullName) -Destination $DestinationFilePath -Force
                    }
                    else
                    {
                        Write-Message "- [Adding] $($File.Name)" -Vrb
                        Copy-Item -Path $($File.FullName) -Destination $DestinationFilePath -Force
                    }
                }
                catch
                {
                    if ($Attempt -lt $MaxAttempts)
                    {
                        Write-Message "- [Warning - $($Attempt)]: Failed to deploy $($File.Name): $($_.Exception.Message)." -Vrb
                        Start-Sleep -Second 1
                    }
                    else
                    {
                        Write-Message "- [Error]: Failed all attempts to deploy $($File.FullName): $($_.Exception.Message)." -Vrb
                        $UpdateErrors += $File
                    }
                }

                $Attempt++
            }
        }

        if ($UpdateErrors.Count -gt 0)
        {
            Write-Message "Error: Failed to deploy $($UpdateErrors.Count) files to Monitoring manifest folder."
            $ErrorMessages += "Failed to deploy $($UpdateErrors.Count) files to Monitoring manifest folder."
            $ExitCode = $ExitCode -bor 32
        }
        else
        {
            Write-Message "Manifest files were all deployed to: $($MonManifestPath)"
        }

        # Start the MonitoringInstall task.
        try
        {
            Write-Message "Starting Monitoring Agent..."
            Start-MonitoringAgent -MaxWaitSec $StartTaskMaxWaitSec -SkipIfNotInstalled
        }
        catch
        {
            Write-Message "Error: Failed to start Monitoring Agent: $($_)"
            $ErrorMessages += "Failed to start Monitoring Agent: $($_)"

            # Set exit code to indicate Monitoring Agent could not be started.
            $ExitCode = $ExitCode -bor 8
        }

        # Throw exception with error messages.
        if ($ErrorMessages.Count -gt 0)
        {
            $ErrorMessage = [string]::Join("; ", $ErrorMessages)
            throw $ErrorMessage
        }
    }
}
catch
{
    # Ensure non-zero exit code if an exception is caught and no exit code set.
    if ($ExitCode -eq 0)
    {
        $ExitCode = 1024
    }

    $ErrorMessage = "Error during ETW update: $($_)"

    Write-Message $ErrorMessage
    Write-Message "$($_.ScriptStackTrace)" -Vrb
    Write-Message "$($_.Exception)" -Vrb
    Write-Message "ETW update script failed with exit code: $($ExitCode)."

    # Use throw to indicate error to AXUpdateInstaller.
    # In case of exceptions, the output is not captured, so only the error message and
    # log file contents will be available for diagnostics.
    throw "$($ErrorMessage) [Log: $($LogPath)]"
}

Write-Message "ETW update script completed with exit code: $($ExitCode)."
exit $ExitCode
# SIG # Begin signature block
# MIIjnwYJKoZIhvcNAQcCoIIjkDCCI4wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDCQRB6wRBeJ1B5
# JkRLQ9dHqgHuYjGz9vL69tiyDhwya6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg0QA4VYYm
# HMZKALYowQDuMDGXMNXodob0c+JMLVPOkvYwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBB05JxqRbw66u+yyHvP4zl/eE3K/7+gMz/DwA1q0Lz
# J6ImmGf0bCwpSVqYoQObfg2JsrxEFSPjEkXVWZ2gFt/EcKGQkmB4vxKJ+Hp49KQk
# yWOt1xmvjZ46AhT4uSoBeekyqKFEuPipCun6nir3f8XQJdjYPPbs8NP8MERYguFV
# n791/X67ev2FCDeSLNeoYrh6TzoSDAnYBuB34mHhfWO+7Dt1gWJ6Hzj5HFONLmh6
# gckYH/e9ksTN/4gzp7vsczGnfUTFv1mq3KFXa6VSY9HVeDK0SKcZwfVBPm5jjyHn
# ttRH9qagEcTmcI2tZ0kfiBJPg1xCXCw1vdjHSPbgmE2QoYIS/jCCEvoGCisGAQQB
# gjcDAwExghLqMIIS5gYJKoZIhvcNAQcCoIIS1zCCEtMCAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIFWIyi45FsAS4lgYy9cQIjOTL2CNHW1WHxIMd1Ae
# H7VfAgZhgwt70xYYEzIwMjExMTExMDMxMzE1LjUxOFowBIACAfSggdikgdUwgdIx
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
# AQQwLwYJKoZIhvcNAQkEMSIEIEurl7D4vTZGFXcBZezy7qdtlD4DDnT3TlauVNnE
# 4ZTTMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgUT8BPIzqc3SecHRPLKBt
# W0vOOnT+78haWo+XcxVerd4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAUGvf1KXXPLcRQAAAAABQTAiBCASf5z2RogRw9kzaPb22MOm
# 4jPdwgnIQDbe07uARxK0ADANBgkqhkiG9w0BAQsFAASCAQDnnG6pKfa566sp5wcP
# PIgwTI1yjC17eFDfrLOJXJh8GKosRDiT+NsOg6D064JAp233FMXqwK9hC5dSNjmY
# 3ctHTwUIkSH4nbqTyXhbD0Lf7ppVv8KrvEFy7D0sT5Zeh5kEx4XeekuOwL+QyOUZ
# tLkVlrQbE4G/X62iwpPN3E3EZBDkHbuJAfmECCM5YPYAV4ogF7lAeOpBTNLQrIp7
# WIXwfGaDj3+378d7kXoSXhhaEtgOzT8rbEht03dKzZ5xHuvdS4WpYhHU69BmrxJI
# UVO5rb7NGlLNMwF8+AieSt2RlRKoQfB619MXkIdfON3OT7zq5VTv1YV0UBRBWg6u
# GqSE
# SIG # End signature block
