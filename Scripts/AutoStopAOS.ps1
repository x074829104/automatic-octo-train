<#
.SYNOPSIS
    Stops the AOS service.

.DESCRIPTION

    Copyright © 2019 Microsoft. All rights reserved.
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false, HelpMessage = "The path to the directory in which to write log files.")]
    [string]$LogDir
)

$ErrorActionPreference = "Stop"
Import-Module WebAdministration
Import-Module "$PSScriptRoot\CommonRollbackUtilities.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\CommonFaultHandling.psm1" -Force

function checkAosKernelFileLocked
{
    Param
    ( 
    [parameter(mandatory=$true,position=0)]
    [string]
    $AosKernelPathParam,
    [parameter(mandatory=$true, position=1)]
    [Int]
    $MaxWaitSecParam 
    )

    $AosKernelLockedFlag = $true

    $StopWatch = [System.Diagnostics.StopWatch]::StartNew()

    while ($AosKernelLockedFlag -and $StopWatch.Elapsed.TotalSeconds -lt $MaxWaitSecParam)
    {
        try
        {
            [IO.File]::OpenWrite($AosKernelPathParam).close()
            $AosKernelLockedFlag = $false
        }
        catch
        {
            Write-ServicingLog "Failed to open $($AosKernelPathParam) for write: $($_.Exception.Message)" -Vrb
            Start-Sleep -Seconds 1
        }
    }

    $StopWatch.Stop()
    return $AosKernelLockedFlag
}

# Initialize exit code.
[int]$ExitCode = 0

# Initialize the log file to use with Write-ServicingLog.
Set-ServicingLog -LogDir $LogDir

try
{
    Write-ServicingLog "Stopping AOS..."

    # For non-admin developer machine scenarios, import module to replace functions that
    # will not work within running as administrator.
    if (Test-Path "$($PSScriptRoot)\NonAdminDevToolsInterject.ps1")
    {
        & "$($PSScriptRoot)\NonAdminDevToolsInterject.ps1"
    }

    # Sometimes Get-Process will throw an exception even when called with a
    # SilentlyContinue error action.
    try
    {
        $devenv = Get-Process -Name "devenv" -ErrorAction SilentlyContinue
    }
    catch
    {
        Write-ServicingLog "Warning: Unable to get devenv processes: $($_)" -Vrb
    }

    # If any devenv processes are found, throw an exception.
    if ($devenv)
    {
        throw "Please close all instance of Visual Studio to continue with the installation."
    }

    # Determine if running in admin or non-admin mode.
    $IsAdmin = Test-IsRunningAsAdministrator

    # Get IIS service and start it if it is not already running.
    $IisService = Get-Service -Name "W3SVC"
    if ($IisService -and $IisService.Status -ine "Running")
    {
        Write-ServicingLog "IIS service is not running, starting IIS Service..."
        Start-Service -Name "W3SVC"
        Write-ServicingLog "IIS service started."
    }

    # Get the AOS web site and app pool and make sure they are both started.
    $websiteName = Get-AosWebsiteName
    $appPoolName = Get-AosAppPoolName
    if ((![string]::IsNullOrWhitespace($websiteName)) -and (![string]::IsNullOrWhitespace($appPoolName)))
    {
        Write-ServicingLog "Stopping IIS AOS web site."
        Stop-Website -Name $websiteName

        # Check if in stopped state before stopping to avoid error.
        $AosWebAppPoolState = Get-WebAppPoolState -Name $appPoolName
        if ($AosWebAppPoolState.Value -ine "Stopped")
        {
            Write-ServicingLog "Stopping IIS AOS application pool."
            Stop-WebAppPool -Name $appPoolName
        }

        # Set properties on web site and app pool, so they do not restart during reboots / IISRESETs.
        # Note: Stopping / starting via IIS mananger GUI will set these same properties.
        # Note: This is not available for non-admin users.
        if ($IsAdmin)
        {
            Write-ServicingLog "Disabling IIS auto start properties for the AOS website and application pool." -Vrb
            Set-ItemProperty -Path "IIS:\Sites\$webSiteName" -Name serverAutoStart -Value $false
            Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name autoStart -Value $false
        }

        $productConfigurationPoolName = Get-ProductConfigurationAppPoolName
        if (![string]::IsNullOrWhitespace($productConfigurationPoolName))
        {
            # Check if in stopped state before stopping to avoid error.
            $ProductConfigurationAppPoolState = Get-WebAppPoolState $productConfigurationPoolName
            if ($ProductConfigurationAppPoolState.Value -ine "Stopped")
            {
                Write-ServicingLog "Stopping IIS product configuration application pool."
                Stop-WebAppPool -Name $productConfigurationPoolName
            }

            # Set property on app pool, so it does not restart during reboots / IISRESETs.
            # Note: Stopping / starting via IIS mananger GUI will set the same property.
            # Note: This is not available for non-admin users.
            if ($IsAdmin)
            {
                Write-ServicingLog "Disabling IIS auto start property for the product configuration application pool." -Vrb
                Set-ItemProperty -Path "IIS:\AppPools\$productConfigurationPoolName" -Name autoStart -Value $false
            }
        }
    }

    # Try to get a list of all xppc* processes and attempt to stop them.
    try
    {
        $XppcProcesses = @(Get-Process -Name "xppc*" -ErrorAction SilentlyContinue)
        if ($XppcProcesses.Count -gt 0)
        {
            Write-ServicingLog "Stopping $($XppcProcesses.Count) 'xppc*' processes..." -Vrb
            foreach ($XppcProcess in $XppcProcesses)
            {
                Write-ServicingLog "Stopping $($XppcProcess.Name) process ID $($XppcProcess.Id)..." -Vrb
                try
                {
                    $XppcProcess | Stop-Process -Force
                }
                catch
                {
                    Write-ServicingLog "Warning: Failed to stop $($XppcProcess.Name) process ID $($XppcProcess.Id): $($_)" -Vrb
                }
            }
        }
    }
    catch
    {
        Write-ServicingLog "Warning: Unable to get xppc processes to stop: $($_)" -Vrb
    }

    # Stop the batch service and set the startup type to disabled, so it does not get started on reboot.
    Write-ServicingLog "Stopping and disabling the batch service."
    
    # Logger to pass to the retry function
    $logger = {param($message) Write-ServicingLog $message}

    # Block to kill batch in the last iteration of the retry function
    $killBatchProcess = {
        #Kill the batch process if still running at the end of the retries.
        $batchSvcName = "DynamicsAxBatch"
        $batchProcess = Get-WmiObject Win32_Service | where {$_.name -eq $batchSvcName}
        if($batchProcess)
        {
          $batchProcessInstance = $batchProcess | Format-List | Out-String
          Write-Output "Found Batch service: $batchProcessInstance"

          $batchProcessId = $batchProcess.ProcessId

          if($batchProcessId -gt 0)
          {
            Write-Output "Stopping Batch process ID: $batchProcessId"
            Stop-Process -Id $batchProcessId -Force
            Start-Sleep 5
          }

          #Final attempt to stop/disable batch
          Write-Output "Final attempt to stop and disable batch after killing the batch process"
          Stop-ServiceAndDisableStartup -ServiceName $batchSvcName
        }
        else
        {
          throw "Unable to find batch service"
        }
      }

    # Attempt to stop batch for up to 7 minutes with incrimental backoff of 4n seconds between attempts
    $output=""
    Invoke-RetryWithBackoff -Command { Stop-ServiceAndDisableStartup -ServiceName "DynamicsAxBatch" } `
                            -Logger $logger `
                            -TimeoutSeconds 420 `
                            -RetryIntervalSec 4 `
                            -TimeoutAction $killBatchProcess `
                            -CommandOutput ([ref]$output) `
                            -TreatTimeoutActionAsSuccess

    if($output -ne "")
    {
       Write-ServicingLog $output
    }

    # Get the AOS web root and find the path to the AOS kernel DLL and check that there are no file
    # locks on it. Throw an exception if there is a lock and it does not go away within the timeout.
    $webroot = Get-AosWebSitePhysicalPath
    $AosKernelPath = Join-Path -Path $webroot -ChildPath "bin\AOSKernel.dll"
    if (Test-Path -Path $AosKernelPath -ErrorAction SilentlyContinue)
    {
        Write-ServicingLog "Validating that $($AosKernelPath) is not locked..." -Vrb

        $AosKernelLocked = $true
        $MaxWaitSec = 300

        $AosKernelLocked = checkAosKernelFileLocked -AosKernelPathParam $AosKernelPath -MaxWaitSecParam $MaxWaitSec

        if ($AosKernelLocked)
        {            
            $w3wpName = "w3wp"
            $axhostName = "axhost"
            $batchname = "Batch"
            $w3wpOraxHostTerminated  = $false

            # Get the locking processes
            Get-Process | foreach {
                $processVar = $_;
                $_.Modules | foreach {
                    if($_.FileName -eq $AosKernelPath)
                    {                        
                        # Terminate w3wp or axhost or batch process
                        if ($processVar.Name -eq $w3wpName -or $processVar.Name -eq $axhostName -or $processVar.Name -eq $batchname)
                        {
                            Write-ServicingLog "Terminate the locking process: $($processVar.Name) PID:$($processVar.id) Locked file:$($AosKernelPath), and try to continue." -Vrb
                            Stop-Process -Id $processVar.Id -Force                            
                            $w3wpOraxHostTerminated = $true
                        }
                    }
                }
            }

            if ($w3wpOraxHostTerminated)
            {
                # Check again for file locking.
                Write-ServicingLog "Revalidating that $($AosKernelPath) is not locked..." -Vrb
                $AosKernelLocked = checkAosKernelFileLocked -AosKernelPathParam $AosKernelPath -MaxWaitSecParam $MaxWaitSec
            }

            # still locked
            if ($AosKernelLocked)
            {
                $LockingProcessFound = $false
                # Get the locking processes
                Get-Process | foreach {
                    $processVar = $_;
                    $_.Modules | foreach {
                        if($_.FileName -eq $AosKernelPath)
                        {
                            $LockingProcessFound = $true
                            Write-ServicingLog "Locking process: $($processVar.Name) PID:$($processVar.id) Locked file:$($AosKernelPath)" -Vrb
                        }
                    }
                }

                $ErrorMessage = "File locks found on $($AosKernelPath) for more than $($MaxWaitSec) seconds."
                if ($LockingProcessFound)
                {
                    $ErrorMessage += " Check previous logs for identified locking processes."
                }
                else
                {
                    $ErrorMessage += " No locking process was able to be automatically identified. Please manually check which processes are keeping a lock on the file."
                }

                throw $ErrorMessage
            }
            else
            {
                Write-ServicingLog "No file locks found on $($AosKernelPath) after terminating processes." -Vrb
            }
        }
        else
        {
            Write-ServicingLog "No file locks found on $($AosKernelPath)." -Vrb
        }
    }
    else
    {
        Write-ServicingLog "Warning: No AOS kernel DLL found at: $($AosKernelPath)." -Vrb
    }
}
catch
{
    # Ensure non-zero exit code if an exception is caught and no exit code set.
    if ($ExitCode -eq 0)
    {
        $ExitCode = 1024
    }

    $ErrorMessage = "Error during AOS stop: $($_)"

    Write-ServicingLog $ErrorMessage
    Write-ServicingLog $($_) -Vrb
    Write-ServicingLog "AOS stop script failed with exit code: $($ExitCode)."

    # Use throw to indicate error to AXUpdateInstaller.
    # In case of exceptions, the output is not captured, so only the error message and
    # log file contents will be available for diagnostics.
    throw "$($ErrorMessage) [Log: $(Get-ServicingLog)]"
}

Write-ServicingLog "AOS stop script completed with exit code: $($ExitCode)."
exit $ExitCode
# SIG # Begin signature block
# MIIjnwYJKoZIhvcNAQcCoIIjkDCCI4wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA25bYQ0dQc0VH6
# EKu4W9dTbOuaZqZwvKZRVHlVmKgNb6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgZ4bxuDkH
# KXOPNZ8537UhGsnZlncfvPMVrQtkGcU5rxIwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCsOLzUpOBQDcuOrCEZ8oNHbp6fBd5rxQjkowrZC0UD
# tCljELNfN6O1R8E+aqIe8XGH9pGp7i9VNdImvku4WEHpum9/k1H+YAkHRTwR98r7
# BIzK0t2XqujTiEFTjcYXm8SMgBqtH0VVvqiCeL4CX/og1GfHSz1jzzSlLOcZ/0Hp
# E1EvVUXgdwlqSjCApVvtuTmUtefsbJTF4ac3IiGnENnCF6R5tnHl0kNTEMmfsmkB
# 5GAEv0W6PJZR9MHBc4ec+u+IU+7M+Z7BzP4DpocLCJoToC6b+kcqftqLwPQkrvqz
# heW7KZFfN/UxmDRkRIeY/5oemhDDd1d6GSxA1KoZAbOvoYIS/jCCEvoGCisGAQQB
# gjcDAwExghLqMIIS5gYJKoZIhvcNAQcCoIIS1zCCEtMCAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIIpg3f4FFbXNpbYKsZpWR/TT7CRzBB/VT7QmHJmV
# lerWAgZhgvJT2u8YEzIwMjExMTExMDMxMzE0LjMxOFowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2Wggg5NMIIE+TCCA+GgAwIBAgITMwAAAT7OyndSxfc0
# KwAAAAABPjANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMDEwMTUxNzI4MjVaFw0yMjAxMTIxNzI4MjVaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjg2REYtNEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvFTEyDzZ
# fpws404gSC0kt4VSyX/vaxwOfri89gQdxvfQNvvQARebKR3plqHz0ZHZW+bmFxyG
# tTh9zw20LSdpMcWYDFc1rzPuJvTNAnDkKyQP+TqrW7j/lDlCLbqi8ubo4EqSpkHr
# a0Zt15j2r/IJGZbu3QaRY6qYMZxxkkw4Y5ubAwV3E1p+TNzFg8nzgJ9kwEM4xvZA
# f9NhHhM2K/jx092xmKxyFfp0X0tboY9d1OyhdCXl8spOigE32g8zH12Y2NXTfI41
# 41LQU+9dKOKQ7YFF1kwofuGGwxMU0CsDimODWgr6VFVcNDd2tQbGubgdfLBGEBfj
# e0PyoOOXEO1m4QIDAQABo4IBGzCCARcwHQYDVR0OBBYEFJNa8534u9BiLWvwtbZU
# DraGiP17MB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRP
# ME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEww
# SgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAKaz+RF9Wp+GkrkVj6cY
# 5djCdVepJFyufABJ1qKlCWXhOoYAcB7w7ZxzRC4Z2iY4bc9QU93sa2YDwhQwFPeq
# fKZfWSkmrcus49QB9EGPc9FwIgfBQK2AJthaYEysTawS40f6yc6w/ybotAclqFAr
# +BPDt0zGZoExvGc8ZpVAZpvSyXbzGLuKtm8K+R73VC4DUp4sRFck1Cx8ILvYdYSN
# YqORyh0Gwi3v4HWmw6HutafFOdFjaKQEcSsn0SNLfY25qOqnu6DL+NAo7z3qD0eB
# DISilWob5dllDcONfsu99UEtOnrbdl292yGNIyxilpI8XGNgGcZxKN6VqLBxAuKl
# WOYwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQsw
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
# bGVzIFRTUyBFU046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAKBMFej0xjCTjCk1sTdT
# Ka+TzJDUoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDlNqrUMCIYDzIwMjExMTExMDQzMjIwWhgPMjAyMTExMTIw
# NDMyMjBaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOU2qtQCAQAwCgIBAAICCoAC
# Af8wBwIBAAICEYAwCgIFAOU3/FQCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQBS+G+sLKwIvW/6saMZinvxUWcc5OD7SIGEt7KI4urckDmjWkBnQCwNJAgRUtVU
# jYMGQRN+3b57DkXAVSpDdXCYApwooEPHx8l8sZH5q5BmwkSMbArVcObUcNERMINk
# m3iWGVnp/C582rqdRXc5SRtj5sN3jrYuBPpx7zTK8Ex8ITGCAw0wggMJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABPs7Kd1LF9zQrAAAA
# AAE+MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIOcL3TatNTK4nzuch6DB5a1AldJVehwBTDEW4HcO
# jc1sMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgi+vOjaqNTvKOZGut49HX
# rqtwUj2ZCnVOurBwfgQxmxMwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAT7OyndSxfc0KwAAAAABPjAiBCDK5j/ygBT/VVeBCNF7uQuv
# WbKtuIPTvU8fC4vn2nReDzANBgkqhkiG9w0BAQsFAASCAQAsst/raKVMsj0S4XuW
# LUoAHaWQCByURyl8H6FcuOWgaxbqC+mCXl1vks8U8LMMscZQof6wl3JzjBPEWJrP
# G5EQ55zGbWa/7ZtZgzl0HZDQSR9FUET0gALtjzi1euKu7BRAqOF0ANeXSlwyUIIB
# MpiYDcyyVhdowxdPp9SQbVZWVB4xSrw0vk7qQ5436d+eBgX2YfbYRoHo/h32UDSD
# 8RMw84fm63GhUtlUYq24EIVinM4GZ/7ohWHBYOkMZ1Ld3CPOY458YEx+6/1A3qEc
# yZJpsAZc4WHwtT20XvIe8k5qxFyqjyrb6vn2Lrsll6u1O6RyZrkEFuxryRhvQQCH
# HTO8
# SIG # End signature block
