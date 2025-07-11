# ---------------------------------
# Function definitions
# ---------------------------------

# Creates a directory with the provided path
function Create-Directory([string]$path)
{
    if (-not(Test-Path -Path $path))
    {
        New-Item -Path $path -ItemType Directory
    }
}

# Deletes a file
function Delete-File([string]$filePath)
{
    if ((-not([string]::IsNullOrWhiteSpace($filePath))) -and (Test-Path -Path $filePath))
    {
        Remove-Item -Path $filePath -force
    }
}

# Replaces a string in a text file
function Replace-StringInFile {
    param (
        [Parameter(Mandatory)]
        [string]$filePath,
        [Parameter(Mandatory)]
        [string]$findString,
        [string]$replaceString
    )

    # Make sure file exists and findString value is not empty
    if ((-not([string]::IsNullOrWhiteSpace($filePath))) -and (Test-Path -Path $filePath) -and -not([string]::IsNullOrWhiteSpace($findString)))
    {
        try
        {
           $reader = [System.IO.StreamReader] $filePath
           $data = $reader.ReadToEnd()
           $reader.close()
        }
        finally
        {
           if ($reader -ne $null)
           {
               $reader.dispose()
           }
        }

        $data = $data.Replace($findString, $replaceString)

        try
        {
           $writer = [System.IO.StreamWriter] $filePath
           $writer.write($data)
           $writer.close()
        }
        finally
        {
           if ($writer -ne $null)
           {
               $writer.dispose()
           }
        }
    }
}

function Set-RetailWebConfigEncryption {
    Param(
    [string] $configurationFilePath,
    [ValidateSet('Decrypt', 'Encrypt')]
    [string] $mode
    )
    $configDirectory = (Get-Location)
    Set-Location $([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())
    switch($mode)
    {
        "Decrypt"{& .\aspnet_regiis.exe -pdf "connectionStrings" "$configurationFilePath"}
        "Encrypt"{& .\aspnet_regiis.exe -pef "connectionStrings" "$configurationFilePath"}
    }
    Set-Location $configDirectory
}

# File name variables
$webConfigFilename = "web.config"
$wifConfigFilename = "wif.config"
$wifServicesConfigFilename = "wif.services.config"
$mrServiceHostExeFileName = "MRServiceHost.exe.config"
$mrServiceHostConnectionsFileName = "MRServiceHost.connections.config"
$mrServiceHostSettingsFileName = "MRServiceHost.settings.config"
$mrDeployConfigFileName = "MRDeploy.config"
$vhdCertificatesFileName = "VhdCertificates.json"
# $ssrsPVMConfigXmlFileName = "ReportPVMConfiguration.xml"
# $commerceRuntimeConfigFileName = "CommerceRuntime.config"
# $retailCertjsonFileName = "Certs.json"

# Define paths
$webRootDirectory = "C:\AOSService\webroot"
$mrServiceDirectory = "c:\FinancialReporting\Server\Services"
$mrConsoleDirectory = "c:\FinancialReporting\Server\Console"
# $commerceRootDirectory = "c:\RetailServer\webroot\bin"
# $RetailRootDirectory = "c:\RetailServer\webroot"
# $RetailAuthRootDirectory = "c:\RetailServer\webroot\Auth\Certs"
# $ssrsRootDirectory = Join-Path -Path $env:ProgramFiles -ChildPath "Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin"
$currentDirectory = Get-Location
$backupDirectory = Join-Path -Path $currentDirectory -ChildPath "Backup"
$workingDirectory = Join-Path -Path $currentDirectory -ChildPath "Working"
# $retailbackupDirectory = Join-Path -Path $currentDirectory -ChildPath "Retail\Backup"
# $retailworkingDirectory = Join-Path -Path $currentDirectory -ChildPath "Retail\Working"

# Create the directories if necessary
Create-Directory $backupDirectory
Create-Directory $workingDirectory
# Create-Directory $retailbackupDirectory
# Create-Directory $retailworkingDirectory

# Define config file paths
$webConfigPath = Join-Path -Path $webRootDirectory -ChildPath $webConfigFilename
$wifConfigPath = Join-Path -Path $webRootDirectory -ChildPath $wifConfigFilename
$wifServicesConfigPath = Join-Path -Path $webRootDirectory -ChildPath $wifServicesConfigFilename
$mrServiceHostExePath = Join-Path -Path $mrServiceDirectory -ChildPath $mrServiceHostExeFileName
$mrServiceHostSettingsPath = Join-Path -Path $mrServiceDirectory -ChildPath $mrServiceHostSettingsFileName
$mrServiceHostConnectionsPath = Join-Path -Path $mrServiceDirectory -ChildPath $mrServiceHostConnectionsFileName
$mrDeployConfigPath = Join-Path -Path $mrConsoleDirectory -ChildPath $mrDeployConfigFileName
# $ssrsPVMConfigXmlPath = Join-Path -Path $ssrsRootDirectory -ChildPath $ssrsPVMConfigXmlFileName
# $commerceConfigPath = Join-Path -Path $commerceRootDirectory -ChildPath $commerceRuntimeConfigFileName
# $retailWebConfigPath = Join-Path -Path $RetailRootDirectory -ChildPath $webConfigFilename
# $retailcertjsonpath = Join-Path -Path $RetailAuthRootDirectory -ChildPath $retailCertjsonFileName

# Copy the config files to the backup AND working directories. 
# The copies in the backup directory will remain as-is, while the
# those in the working folder will be operated on.
# adding reporting XML for SSRS

Copy-Item -Path $webConfigPath -Destination $backupDirectory -Force
Copy-Item -Path $wifConfigPath -Destination $backupDirectory -Force
Copy-Item -Path $wifServicesConfigPath -Destination $backupDirectory -Force

Copy-Item -Path $mrServiceHostExePath -Destination $backupDirectory -Force
Copy-Item -Path $mrServiceHostSettingsPath -Destination $backupDirectory -Force
Copy-Item -Path $mrServiceHostConnectionsPath -Destination $backupDirectory -Force
Copy-Item -Path $mrDeployConfigPath -Destination $backupDirectory -Force

# Copy-Item -Path $ssrsPVMConfigXmlPath -Destination $backupDirectory -Force
# Copy-Item -Path $commerceConfigPath -Destination $backupDirectory -Force
# Copy-Item -Path $retailWebConfigPath -Destination $retailbackupDirectory -Force

Copy-Item -Path $webConfigPath -Destination $workingDirectory -Force
Copy-Item -Path $wifConfigPath -Destination $workingDirectory -Force
Copy-Item -Path $wifServicesConfigPath -Destination $workingDirectory -Force

Copy-Item -Path $mrServiceHostExePath -Destination $workingDirectory -Force
Copy-Item -Path $mrServiceHostSettingsPath -Destination $workingDirectory -Force
Copy-Item -Path $mrServiceHostConnectionsPath -Destination $workingDirectory -Force
Copy-Item -Path $mrDeployConfigPath -Destination $workingDirectory -Force

# Copy-Item -Path $ssrsPVMConfigXmlPath -Destination $workingDirectory -Force
# Copy-Item -Path $commerceConfigPath -Destination $workingDirectory -Force
# Copy-Item -Path $retailWebConfigPath -Destination $retailworkingDirectory -Force
# Copy-Item -Path $retailcertjsonpath -Destination $retailworkingDirectory -Force

# Define working file paths
$webConfigWorkingPath = Join-Path -Path $workingDirectory -ChildPath $webConfigFilename
$wifConfigWorkingPath = Join-Path -Path $workingDirectory -ChildPath $wifConfigFilename
$wifServicesConfigWorkingPath = Join-Path -Path $workingDirectory -ChildPath $wifServicesConfigFilename
$mrServiceHostExeWorkingPath = Join-Path -Path $workingDirectory -ChildPath $mrServiceHostExeFileName
$mrServiceHostSettingsWorkingPath = Join-Path -Path $workingDirectory -ChildPath $mrServiceHostSettingsFileName
$mrServiceHostConnectionsWorkingPath = Join-Path -Path $workingDirectory -ChildPath $mrServiceHostConnectionsFileName
# $ssrsPVMConfigXmlWorkingPath = Join-Path -Path $workingDirectory -ChildPath $ssrsPVMConfigXmlFileName
# $commerceConfigWorkingPath = Join-Path -Path $workingDirectory -ChildPath $commerceRuntimeConfigFileName
$mrDeployConfigWorkingPath = Join-Path -Path $workingDirectory -ChildPath $mrDeployConfigFileName

# $retailWebConfigWorkingPath = Join-Path -Path $retailworkingDirectory -ChildPath $webConfigFilename
# $retailcertauthWorkingPath = Join-Path -Path $retailworkingDirectory -ChildPath $retailCertjsonFileName

# Define path of resultant VhdCertificates.json file
$vhdCertificatesPath = Join-Path -Path $currentDirectory -ChildPath $vhdCertificatesFileName

# Load certificate info in json object
$certificates = Get-Content ".\Certificates.json" | Out-String | ConvertFrom-Json

# Decryption utility
$decryptionToolPath = Join-Path -Path $webRootDirectory -ChildPath "bin\Microsoft.Dynamics.AX.Framework.ConfigEncryptor.exe"

# Get installed machine certificates
$localMachineCertificates = Get-ChildItem -Path Cert:\LocalMachine\My

# Build the Json array containing certificate information
# Output certificate subject, subject alternate name and semaphore
[string]$certInfo = ""

ForEach ($lmCertificate in $localMachineCertificates)
{
    ForEach ($certificate in $certificates)
    {
        if ($lmCertificate.Subject.Contains($certificate.SubjectName))
        {
            if (-not([string]::IsNullOrWhiteSpace($certInfo)))
            {
                $certInfo = [string]::Concat($certInfo, ",")
            }

            $certInfo = [string]::Concat($certInfo, '{')

            $certInfo = [string]::Concat($certInfo, '"Semaphore": ', '"', "$($certificate.Semaphore)", '"')

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"SubjectName": ', '"', "$($lmCertificate.Subject)", '"')
            
            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"Thumbprint": ', '"', "$($lmCertificate.Thumbprint)", '"')

            $certSan = ""
            $sanObj = ($lmCertificate.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"})
            if($null -ne $sanObj)
            {
                $certSan = ($lmCertificate.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"}).Format(1)
            }

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"SubjectAlternateName": ', '"', $certSan, '"')

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"SignatureAlgorithm": ', '"', "$($lmCertificate.SignatureAlgorithm.FriendlyName)", '"')

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"PublicKey": ', '"', "$($lmCertificate.PublicKey.Oid.FriendlyName)", '"')

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"KeyLength": ', '"', "$($lmCertificate.PublicKey.Key.KeySize)", '"')

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"EnhancedKeyUsageList": ', '"', "$($lmCertificate.EnhancedKeyUsageList)", '"')

            $DnsNameListFormatted = ""
            if($null -ne $lmCertificate.DnsNameList)
            {
                [string]$DnsNameList = $lmCertificate.DnsNameList
                $DnsNameList = $DnsNameList.Trim()
                $DnsNameListFormatted = $DnsNameList.Replace(" ",",")
            }

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"DnsNameList": ', '"', "$DnsNameListFormatted", '"')

            $extensionsList = ""
            Foreach ($extension in $lmCertificate.Extensions)
            {
                if (-not([string]::IsNullOrWhiteSpace($extensionsList)))
                {
                    $extensionsList = [string]::Concat($extensionsList, ',')
                }

                $extensionsList = [string]::Concat($extensionsList, $extension.Oid.FriendlyName)
            }

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"Extensions": ', '"', "$($extensionsList)", '"')

            $certInfo = [string]::Concat($certInfo, ',')
            $certInfo = [string]::Concat($certInfo, '"Issuer": ', '"', "$($lmCertificate.Issuer)", '"')

            $certInfo = [string]::Concat($certInfo, '}')
        }
    }
}

$certInfo = "[" + $certInfo + "]"

# Convert the Json string into an object and output to file
$jsonStr = $certInfo | ConvertFrom-Json | ConvertTo-Json -Depth 10

# Perform a bit of cleanup such that the resultant string is array only
$sb = [System.Text.StringBuilder]::new()
$lines = $jsonStr -split "`r`n"

foreach ($line in $lines)
{
    if ((-not($line.StartsWith("{"))) -and (-not($line.StartsWith("}"))) -and (-not($line.Contains('"Count":'))))
    {
        if ($line.Contains('"value":'))
        {
            $sb.AppendLine("[")
        }
        elseif ($line.Contains('],'))
        {
            $sb.AppendLine("]")
        }
        else
        {
            $sb.AppendLine($line.Substring(15))
        }
    }
}

# Write contents to the json file. This is the file that will be used to build the empty VHD provided to customers
$stream = [System.IO.StreamWriter]::new($vhdCertificatesPath)
$stream.Write($sb.ToString())
$stream.Close()

# Decrypt the web.config file
Start-Process -FilePath $decryptionToolPath -ArgumentList @("-decrypt", $webConfigWorkingPath) -Wait
# Start-Process -FilePath $decryptionToolPath -ArgumentList @("-decrypt", $retailWebConfigWorkingPath) -Wait
# Set-RetailWebConfigEncryption $retailworkingDirectory "Decrypt"

[xml]$webConfigContent = Get-Content -Path $webConfigWorkingPath
$AOSDBUserSecret = ($webConfigContent.configuration.appSettings.add | Where-Object {$_.key -eq "DataAccess.SqlPwd"}).Value

# [xml]$retailwebConfigContent = Get-Content -Path $retailwebConfigWorkingPath
# $RetailDBUserSecret = ($retailwebConfigContent.configuration.appSettings.add | Where-Object {$_.key -eq "DataAccess.SqlPwd"}).Value
# $RetailAdminUserSecret = ($retailwebConfigContent.configuration.appSettings.add | Where-Object {$_.key -eq "DataAccess.axAdminSqlPwd"}).Value
# Replace-StringInFile -filePath $retailWebConfigWorkingPath -findString "RetailWebSite@123" -replaceString "[AOSDBCRED]"

# Offline fake acs Cert thumbprint clean up
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Dynamics\AX7\Development\Configurations' -Name offlineDevCertThumbprint -Value '[FAKE ACS CERT THUMBPRINT]'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Dynamics\AX7\Development\Configurations' -Name offlineDevCertThumbprint -Value '[FAKE ACS CERT THUMBPRINT]'

# Replace secret/certificate information in configuration files with their respective semaphores
ForEach ($lmCertificate in $localMachineCertificates)
{
    ForEach ($certificate in $certificates)
    {
        if($certificate.SubjectName -eq $lmCertificate.Subject)
        {
            Write-Host "Replacing thumbprint of $($certificate.SubjectName) with $($certificate.Semaphore)"

            # Find uses in the config files and replace with a semaphore
            Replace-StringInFile -filePath $webConfigWorkingPath -findString "BA107E921C49852B6A89F5DF8F59EA5501B18392" -replaceString ""
            Replace-StringInFile -filePath $webConfigWorkingPath -findString $AOSDBUserSecret -replaceString "[AOSDBCRED]"
            Replace-StringInFile -filePath $webConfigWorkingPath -findString "00000015-0000-0000-c000-000000000000" -replaceString "[APPLICATIONID]"
            Replace-StringInFile -filePath $webConfigWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            Replace-StringInFile -filePath $wifConfigWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            Replace-StringInFile -filePath $wifConfigWorkingPath -findString "00000015-0000-0000-c000-000000000000" -replaceString "[APPLICATIONID]"
            Replace-StringInFile -filePath $wifServicesConfigWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            Replace-StringInFile -filePath $wifServicesConfigWorkingPath -findString "00000015-0000-0000-c000-000000000000" -replaceString "[APPLICATIONID]"
            Replace-StringInFile -filePath $mrServiceHostExeWorkingPath -findString "BA107E921C49852B6A89F5DF8F59EA5501B18392" -replaceString ""
            Replace-StringInFile -filePath $mrServiceHostExeWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            Replace-StringInFile -filePath $mrServiceHostSettingsWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            Replace-StringInFile -filePath $mrServiceHostSettingsWorkingPath -findString "00000015-0000-0000-c000-000000000000" -replaceString "[APPLICATIONID]"
            Replace-StringInFile -filePath $mrDeployConfigWorkingPath -findString "00000015-0000-0000-c000-000000000000" -replaceString "[APPLICATIONID]"
            Replace-StringInFile -filePath $mrDeployConfigWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            # SSRS config cleanup
            # Replace-StringInFile -filePath $ssrsPVMConfigXmlWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            # Commerce config cleanup
            # Replace-StringInFile -filePath $commerceConfigWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            # retail config cleanup
            # Replace-StringInFile -filePath $retailWebConfigWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            # Replace-StringInFile -filePath $retailWebConfigWorkingPath -findString $RetailDBUserSecret -replaceString "[AOSDBCRED]"
            # Replace-StringInFile -filePath $retailWebConfigWorkingPath -findString $RetailAdminUserSecret -replaceString "[AOSDBCRED]"
            # Replace-StringInFile -filePath $retailcertauthWorkingPath -findString $lmCertificate.Thumbprint -replaceString $certificate.Semaphore
            # Remove certificates from the machine
            $certPath = "Cert:\LocalMachine\My\$($lmCertificate.Thumbprint)"
            $certrootPath = "Cert:\LocalMachine\Root\$($lmCertificate.Thumbprint)"
            if(Test-Path -Path $certPath)
            {
                ##Remove each internal cert found
                Write-Host "Found $($lmCertificate.Subject) at $certPath ... now removing"
                #Need to remove the cert from the old certs from root also
                Get-ChildItem -Path $certPath | Remove-Item -Force
                #Need to remove the cert from the old certs from root also
                Get-ChildItem -Path $certrootPath | Remove-Item -Force
            }
        }
    }
}

# Final Clean-up
Remove-Item -Path $backupDirectory -Recurse
# Remove-Item -Path $retailbackupDirectory -Recurse
# SIG # Begin signature block
# MIIsAAYJKoZIhvcNAQcCoIIr8TCCK+0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD29GUBrqoW6VFS
# pd1yRh7EbgKfF4cLfTWImqrlVO+ELqCCEW4wggh+MIIHZqADAgECAhM2AAAB33OB
# lxa+Mv0NAAIAAAHfMA0GCSqGSIb3DQEBCwUAMEExEzARBgoJkiaJk/IsZAEZFgNH
# QkwxEzARBgoJkiaJk/IsZAEZFgNBTUUxFTATBgNVBAMTDEFNRSBDUyBDQSAwMTAe
# Fw0yNDAxMjAwMTMzNDRaFw0yNTAxMTkwMTMzNDRaMCQxIjAgBgNVBAMTGU1pY3Jv
# c29mdCBBenVyZSBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQDVucAmkbIWpspYysyydQyyRh2L8q5igYFcy2vDk8xGvVMRBhxwbOsJIEd0
# wY8N7WU/xgkYMnSsM4vmc2B49DGdrAjSJqbsx0zf+DLFjrBITUecdRhlq0VKGX8U
# bVOkg0aIfFNLRs4DSrCZYh26zyB8qkL/jUmB7DhcBEhhgOlXRQ4LHnUv7qf+iXqD
# uwFz9tUTAh8JGsgLRBK0oSsRfUB+FJF2KyUxzmeFXJKiEynsWz4kqoM91ag1Yw0U
# 8d0e+RgAKi3Ft1cXA+3qKM6I1H11e/NdIjh7oThvrBtfEngwlwbTF3KZOHdhLBFZ
# 18U4v8VeTlb4r94346CY2+SKnQa7AgMBAAGjggWKMIIFhjApBgkrBgEEAYI3FQoE
# HDAaMAwGCisGAQQBgjdbAQEwCgYIKwYBBQUHAwMwPQYJKwYBBAGCNxUHBDAwLgYm
# KwYBBAGCNxUIhpDjDYTVtHiE8Ys+hZvdFs6dEoFgg93NZoaUjDICAWQCAQ4wggJ2
# BggrBgEFBQcBAQSCAmgwggJkMGIGCCsGAQUFBzAChlZodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpaW5mcmEvQ2VydHMvQlkyUEtJQ1NDQTAxLkFNRS5HQkxfQU1F
# JTIwQ1MlMjBDQSUyMDAxKDIpLmNydDBSBggrBgEFBQcwAoZGaHR0cDovL2NybDEu
# YW1lLmdibC9haWEvQlkyUEtJQ1NDQTAxLkFNRS5HQkxfQU1FJTIwQ1MlMjBDQSUy
# MDAxKDIpLmNydDBSBggrBgEFBQcwAoZGaHR0cDovL2NybDIuYW1lLmdibC9haWEv
# QlkyUEtJQ1NDQTAxLkFNRS5HQkxfQU1FJTIwQ1MlMjBDQSUyMDAxKDIpLmNydDBS
# BggrBgEFBQcwAoZGaHR0cDovL2NybDMuYW1lLmdibC9haWEvQlkyUEtJQ1NDQTAx
# LkFNRS5HQkxfQU1FJTIwQ1MlMjBDQSUyMDAxKDIpLmNydDBSBggrBgEFBQcwAoZG
# aHR0cDovL2NybDQuYW1lLmdibC9haWEvQlkyUEtJQ1NDQTAxLkFNRS5HQkxfQU1F
# JTIwQ1MlMjBDQSUyMDAxKDIpLmNydDCBrQYIKwYBBQUHMAKGgaBsZGFwOi8vL0NO
# PUFNRSUyMENTJTIwQ0ElMjAwMSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2Vy
# dmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1BTUUsREM9R0JM
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MB0GA1UdDgQWBBSO7i0qme7tjtjFjyuIjlmGM6cbCTAOBgNVHQ8BAf8E
# BAMCB4AwRQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEWMBQGA1UEBRMNMjM2MTY3KzUwMTk3MDCCAeYGA1UdHwSCAd0wggHZMIIB
# 1aCCAdGgggHNhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpaW5mcmEvQ1JM
# L0FNRSUyMENTJTIwQ0ElMjAwMSgyKS5jcmyGMWh0dHA6Ly9jcmwxLmFtZS5nYmwv
# Y3JsL0FNRSUyMENTJTIwQ0ElMjAwMSgyKS5jcmyGMWh0dHA6Ly9jcmwyLmFtZS5n
# YmwvY3JsL0FNRSUyMENTJTIwQ0ElMjAwMSgyKS5jcmyGMWh0dHA6Ly9jcmwzLmFt
# ZS5nYmwvY3JsL0FNRSUyMENTJTIwQ0ElMjAwMSgyKS5jcmyGMWh0dHA6Ly9jcmw0
# LmFtZS5nYmwvY3JsL0FNRSUyMENTJTIwQ0ElMjAwMSgyKS5jcmyGgb1sZGFwOi8v
# L0NOPUFNRSUyMENTJTIwQ0ElMjAwMSgyKSxDTj1CWTJQS0lDU0NBMDEsQ049Q0RQ
# LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
# Z3VyYXRpb24sREM9QU1FLERDPUdCTD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0
# P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwHwYDVR0jBBgw
# FoAUllGE4Gtve/7YBqvD8oXmKa5q+dQwHwYDVR0lBBgwFgYKKwYBBAGCN1sBAQYI
# KwYBBQUHAwMwDQYJKoZIhvcNAQELBQADggEBAJe/YXNSCoXitLf/X5pfJZpep3cs
# jdqmBgg+8Kr++8XMjWwdm4tiLasJMUPCgmp5NYn3wC4GefGYwfF7Xm2FMSR2i6QU
# HjigGu6BjdWQh4EwGaNqXLkXlUM7Ww2Z0KrRtpCL16DCOTNZuCFPAytSHFskPWrr
# 6q3EBuiM6P5VLgFSKiAxcunldJorbrBrvZSZib1OINzFGAQszUR0ytovW6FOp+uo
# VhiQCqnOheC1ppnZPss7vnXoogyO0xgSW40bRlltGfwnlOd3IZ/43ZOj5XeeShg5
# 2SzVEiyYrZjD17MSNzQM1JKI07+mtAC7D+eZ/+g2pM/91oHcrDq9Nq4QrS0wggjo
# MIIG0KADAgECAhMfAAAAUeqP9pxzDKg7AAAAAABRMA0GCSqGSIb3DQEBCwUAMDwx
# EzARBgoJkiaJk/IsZAEZFgNHQkwxEzARBgoJkiaJk/IsZAEZFgNBTUUxEDAOBgNV
# BAMTB2FtZXJvb3QwHhcNMjEwNTIxMTg0NDE0WhcNMjYwNTIxMTg1NDE0WjBBMRMw
# EQYKCZImiZPyLGQBGRYDR0JMMRMwEQYKCZImiZPyLGQBGRYDQU1FMRUwEwYDVQQD
# EwxBTUUgQ1MgQ0EgMDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
# mlIJfQGejVbXKpcyFPoFSUllalrinfEV6JMc7i+bZDoL9rNHnHDGfJgeuRIYO1LY
# /1f4oMTrhXbSaYRCS5vGc8145WcTZG908bGDCWr4GFLc411WxA+Pv2rteAcz0eHM
# H36qTQ8L0o3XOb2n+x7KJFLokXV1s6pF/WlSXsUBXGaCIIWBXyEchv+sM9eKDsUO
# LdLTITHYJQNWkiryMSEbxqdQUTVZjEz6eLRLkofDAo8pXirIYOgM770CYOiZrcKH
# K7lYOVblx22pdNawY8Te6a2dfoCaWV1QUuazg5VHiC4p/6fksgEILptOKhx9c+ia
# piNhMrHsAYx9pUtppeaFAgMBAAGjggTcMIIE2DASBgkrBgEEAYI3FQEEBQIDAgAC
# MCMGCSsGAQQBgjcVAgQWBBQSaCRCIUfL1Gu+Mc8gpMALI38/RzAdBgNVHQ4EFgQU
# llGE4Gtve/7YBqvD8oXmKa5q+dQwggEEBgNVHSUEgfwwgfkGBysGAQUCAwUGCCsG
# AQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNxQCAQYJKwYBBAGCNxUGBgorBgEEAYI3
# CgMMBgkrBgEEAYI3FQYGCCsGAQUFBwMJBggrBgEFBQgCAgYKKwYBBAGCN0ABAQYL
# KwYBBAGCNwoDBAEGCisGAQQBgjcKAwQGCSsGAQQBgjcVBQYKKwYBBAGCNxQCAgYK
# KwYBBAGCNxQCAwYIKwYBBQUHAwMGCisGAQQBgjdbAQEGCisGAQQBgjdbAgEGCisG
# AQQBgjdbAwEGCisGAQQBgjdbBQEGCisGAQQBgjdbBAEGCisGAQQBgjdbBAIwGQYJ
# KwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAUKV5RXmSuNLnrrJwNp4x1AdEJCygwggFoBgNV
# HR8EggFfMIIBWzCCAVegggFToIIBT4YxaHR0cDovL2NybC5taWNyb3NvZnQuY29t
# L3BraWluZnJhL2NybC9hbWVyb290LmNybIYjaHR0cDovL2NybDIuYW1lLmdibC9j
# cmwvYW1lcm9vdC5jcmyGI2h0dHA6Ly9jcmwzLmFtZS5nYmwvY3JsL2FtZXJvb3Qu
# Y3JshiNodHRwOi8vY3JsMS5hbWUuZ2JsL2NybC9hbWVyb290LmNybIaBqmxkYXA6
# Ly8vQ049YW1lcm9vdCxDTj1BTUVSb290LENOPUNEUCxDTj1QdWJsaWMlMjBLZXkl
# MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUFNRSxE
# Qz1HQkw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNz
# PWNSTERpc3RyaWJ1dGlvblBvaW50MIIBqwYIKwYBBQUHAQEEggGdMIIBmTBHBggr
# BgEFBQcwAoY7aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraWluZnJhL2NlcnRz
# L0FNRVJvb3RfYW1lcm9vdC5jcnQwNwYIKwYBBQUHMAKGK2h0dHA6Ly9jcmwyLmFt
# ZS5nYmwvYWlhL0FNRVJvb3RfYW1lcm9vdC5jcnQwNwYIKwYBBQUHMAKGK2h0dHA6
# Ly9jcmwzLmFtZS5nYmwvYWlhL0FNRVJvb3RfYW1lcm9vdC5jcnQwNwYIKwYBBQUH
# MAKGK2h0dHA6Ly9jcmwxLmFtZS5nYmwvYWlhL0FNRVJvb3RfYW1lcm9vdC5jcnQw
# gaIGCCsGAQUFBzAChoGVbGRhcDovLy9DTj1hbWVyb290LENOPUFJQSxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPUFNRSxEQz1HQkw/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNl
# cnRpZmljYXRpb25BdXRob3JpdHkwDQYJKoZIhvcNAQELBQADggIBAFAQI7dPD+jf
# XtGt3vJp2pyzA/HUu8hjKaRpM3opya5G3ocprRd7vdTHb8BDfRN+AD0YEmeDB5HK
# QoG6xHPI5TXuIi5sm/LeADbV3C2q0HQOygS/VT+m1W7a/752hMIn+L4ZuyxVeSBp
# fwf7oQ4YSZPh6+ngZvBHgfBaVz4O9/wcfw91QDZnTgK9zAh9yRKKls2bziPEnxeO
# ZMVNaxyV0v152PY2xjqIafIkUjK6vY9LtVFjJXenVUAmn3WCPWNFC1YTIIHw/mD2
# cTfPy7QA1pT+GPARAKt0bKtq9aCd/Ym0b5tPbpgCiRtzyb7fbNS1dE740re0COE6
# 7YV2wbeo2sXixzvLftH8L7s9xv9wV+G22qyKt6lmKLjFK1yMw4Ni5fMabcgmzRvS
# jAcbqgp3tk4a8emaaH0rz8MuuIP+yrxtREPXSqL/C5bzMzsikuDW9xH10graZzSm
# PjilzpRfRdu20/9UQmC7eVPZ4j1WNa1oqPHfzET3ChIzJ6Q9G3NPCB+7KwX0OQmK
# yv7IDimj8U/GlsHD1z+EF/fYMf8YXG15LamaOAohsw/ywO6SYSreVW+5Y0mzJutn
# BC9Cm9ozj1+/4kqksrlhZgR/CSxhFH3BTweH8gP2FEISRtShDZbuYymynY1un+Ry
# fiK9+iVTLdD1h/SxyxDpZMtimb4CgJQlMYIZ6DCCGeQCAQEwWDBBMRMwEQYKCZIm
# iZPyLGQBGRYDR0JMMRMwEQYKCZImiZPyLGQBGRYDQU1FMRUwEwYDVQQDEwxBTUUg
# Q1MgQ0EgMDECEzYAAAHfc4GXFr4y/Q0AAgAAAd8wDQYJYIZIAWUDBAIBBQCgga4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINETKUV9zRQaJcbp6vX6oc2/fEAHQCEN
# JxbBfIwMN+p/MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYA
# dKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEA
# BzcMXE60WFnrWieUwn30gwbPm/JcCp92f6jb81HEJpgTqtYgO2usfxwxOvfQ20ei
# Iy4Zo30aLJ1hWLveUiKYsfHt+PgclaqOB4QQpRp7U5YPLvCAQ7alokN8LcQAJDDd
# 6W/uMnsFvJcTvvss/vGSaKgAja1TeTIIrD28AK2WcjdoGZYEZCArl0hdxnvL9tES
# K3C8mx92egpnQiGMvuerf1NambQwKWa9HBpuKnCQ3+4H8iEVVuYulYXhDnB8CSxI
# Qw/iQ+jLxt37LMCAF40gQZ09NbJaNzvtFCFWKQ3C6IKnDQwkIueRjra17h6vRxNP
# lMCCvedN99Mv4FuSuGOOeaGCF7AwghesBgorBgEEAYI3AwMBMYIXnDCCF5gGCSqG
# SIb3DQEHAqCCF4kwgheFAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFaBgsqhkiG9w0B
# CRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
# BCD39KYbG8pA6gQwP/h+2TH1ZnkJEdXjwz5nMQaTHhRieQIGZ2LBHFsaGBMyMDI0
# MTIxOTIwMTAwNi4xNzRaMASAAgH0oIHZpIHWMIHTMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjoyRDFB
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEf4wggcoMIIFEKADAgECAhMzAAAB/XP5aFrNDGHtAAEAAAH9MA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI0MDcyNTE4
# MzExNloXDTI1MTAyMjE4MzExNlowgdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjJEMUEtMDVFMC1E
# OTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoWWs+D+Ou4JjYnRHRedu0MTFYzNJ
# EVPnILzc02R3qbnujvhZgkhp+p/lymYLzkQyG2zpxYceTjIF7HiQWbt6FW3ARkBr
# thJUz05ZnKpcF31lpUEb8gUXiD2xIpo8YM+SD0S+hTP1TCA/we38yZ3BEtmZtcVn
# aLRp/Avsqg+5KI0Kw6TDJpKwTLl0VW0/23sKikeWDSnHQeTprO0zIm/btagSYm3V
# /8zXlfxy7s/EVFdSglHGsUq8EZupUO8XbHzz7tURyiD3kOxNnw5ox1eZX/c/XmW4
# H6b4yNmZF0wTZuw37yA1PJKOySSrXrWEh+H6++Wb6+1ltMCPoMJHUtPP3Cn0CNcN
# vrPyJtDacqjnITrLzrsHdOLqjsH229Zkvndk0IqxBDZgMoY+Ef7ffFRP2pPkrF1F
# 9IcBkYz8hL+QjX+u4y4Uqq4UtT7VRnsqvR/x/+QLE0pcSEh/XE1w1fcp6Jmq8RnH
# EXikycMLN/a/KYxpSP3FfFbLZuf+qIryFL0gEDytapGn1ONjVkiKpVP2uqVIYj4V
# iCjy5pLUceMeqiKgYqhpmUHCE2WssLLhdQBHdpl28+k+ZY6m4dPFnEoGcJHuMcIZ
# nw4cOwixojROr+Nq71cJj7Q4L0XwPvuTHQt0oH7RKMQgmsy7CVD7v55dOhdHXdYs
# yO69dAdK+nWlyYcCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTpDMXA4ZW8+yL2+3vA
# 6RmU7oEKpDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8E
# WDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9N
# aWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYB
# BQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4G
# A1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAY9hYX+T5AmCrYGaH96Td
# R5T52/PNOG7ySYeopv4flnDWQLhBlravAg+pjlNv5XSXZrKGv8e4s5dJ5WdhfC9y
# wFQq4TmXnUevPXtlubZk+02BXK6/23hM0TSKs2KlhYiqzbRe8QbMfKXEDtvMoHSZ
# T7r+wI2IgjYQwka+3P9VXgERwu46/czz8IR/Zq+vO5523Jld6ssVuzs9uwIrJhfc
# YBj50mXWRBcMhzajLjWDgcih0DuykPcBpoTLlOL8LpXooqnr+QLYE4BpUep3JySM
# YfPz2hfOL3g02WEfsOxp8ANbcdiqM31dm3vSheEkmjHA2zuM+Tgn4j5n+Any7IOD
# YQkIrNVhLdML09eu1dIPhp24lFtnWTYNaFTOfMqFa3Ab8KDKicmp0AthRNZVg0BP
# AL58+B0UcoBGKzS9jscwOTu1JmNlisOKkVUVkSJ5Fo/ctfDSPdCTVaIXXF7l40k1
# cM/X2O0JdAS97T78lYjtw/PybuzX5shxBh/RqTPvCyAhIxBVKfN/hfs4CIoFaqWJ
# 0r/8SB1CGsyyIcPfEgMo8ceq1w5Zo0JfnyFi6Guo+z3LPFl/exQaRubErsAUTfyB
# Y5/5liyvjAgyDYnEB8vHO7c7Fg2tGd5hGgYs+AOoWx24+XcyxpUkAajDhky9Dl+8
# JZTjts6BcT9sYTmOodk/SgIwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAA
# AAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBB
# dXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YB
# f2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKD
# RLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus
# 9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTj
# kY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56
# KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39
# IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHo
# vwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJo
# LhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMh
# XV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREd
# cu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEA
# AaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqn
# Uv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnp
# cjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0w
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEw
# CwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/o
# olxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNy
# b3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5j
# cnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+
# TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2Y
# urYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4
# U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJ
# w7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb
# 30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ
# /gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGO
# WhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFE
# fnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJ
# jXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rR
# nj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUz
# WLOhcGbyoYIDWTCCAkECAQEwggEBoYHZpIHWMIHTMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjoyRDFB
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaIjCgEBMAcGBSsOAwIaAxUAoj0WtVVQUNSKoqtrjinRAsBUdoOggYMwgYCkfjB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsFAAIFAOsO
# kQgwIhgPMjAyNDEyMTkxMjMzMTJaGA8yMDI0MTIyMDEyMzMxMlowdzA9BgorBgEE
# AYRZCgQBMS8wLTAKAgUA6w6RCAIBADAKAgEAAgI72AIB/zAHAgEAAgITzDAKAgUA
# 6w/iiAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IBAQCA0WKbdi4gdkC46Jw4
# ftIKW0IGVVQn2ZheyrezONHQ6PztpdM0jrK29mQPyJxGeDgSnbPQ1BJe8aoSm9ic
# rZHiI0tPg4xTXanDO3afB0vT8KWSiYzrvLJDEE9qutKQr/PwjVEntDsxMnHfKcgg
# tgAu9BTvTUt/KKx35K3LSOz2GP0LlvjGolGYLc3HTV5EmU24Nm9H2aD0ploUBLf/
# IFgpTUsjwRE1Apufpbc656QDKTi5IvBVXLLjYgwwADQtSnC9zAaAn10nrKYF5Mg3
# VK1Gsc24rL6PtfscR/ux0ahCY/DQR0XGONeDkXQ/6te8sKC73xpVlp3/X3+NJOH5
# xTcQMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAC
# EzMAAAH9c/loWs0MYe0AAQAAAf0wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3
# DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgCBz/E5kPQteUWX5P
# mSWaX6jSdDpDUSY8PEFhHPC9lLYwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9
# BCCAKEgNyUowvIfx/eDfYSupHkeF1p6GFwjKBs8lRB4NRzCBmDCBgKR+MHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB/XP5aFrNDGHtAAEAAAH9MCIE
# IKdTNiUpJz4LGDopG0BIbIiQQcK081YJaQ9dAq2Vv+wOMA0GCSqGSIb3DQEBCwUA
# BIICAGUpxRz1AzAuVBVg+p7zvv8OotGUdkhGi4RAkM0dlZGX/wEJExlAEwtjRoVP
# LtZz9l7fvm06WHyjzR7oNRVzGZPnHHOGzw2aJjK7Ie+G4IaBJ9kBzz46E7S8edVo
# jTVXP5N7utZ0SRyz0qNyk4Q1lQHJvCiG3kJQh9Ijmqij9I1KUonfLyljq5PYZaqu
# eCTq8BiFAfCPUcxp8ZsPHZnxvxx4EIwGThKiR9vS68rW4vUn18MS8LzDAXAiAYdF
# KwYjmC75W17Pqm1/NnInST1X55D9tt2QR7jgXZULKOcfhoxxUlQQDwCMLLMaTeue
# NtnfL/iZFgVn5EcthwFm6txWE85BGqXn25660BscPwEMqF0K1PJo7NlHMwxqrXo2
# VIna2c7io7Zxwv1PPuY3idfqs08ZCDsTiz+iYXQNdvWF+ghaa3okLD7JSr3HZGrm
# +2VmWFkI74SwAv0t3A4r9AXa1gagzOdVr+kLD724g+n9dLJSo+GAQFxhd1L2WcYo
# fQSTUIWufGpoz8pjvlo88CACw1GZZG3b4qy2gCtKNfd7wD1U1txNUn6u88LvlsZC
# g551AU6S2HPg3oijZhWlm7pARIBFKBtGBH/HYTTDp9c+/8BXHT1QfN760HLAxgLa
# q+e44Yixi7zXm72oawnH5m7L87lkip2+1cZcvlLlRQ7CsuBt
# SIG # End signature block
