<#
.SYNOPSIS
	
Provides operations and functions for the retrieval of KeyVault Keys and Passwords as
well as some other utilities for manipulating the data that is returned.

.DESCRIPTION

Provides a common module for AX Setup to retrieve and manipulate Azure Secret/Keys.

.PARAMETER VaultName

The Name of the KeyVault you want to retrieve the key from. Azure specifies that a 
KeyVault name must match this regex "^[a-zA-Z0-9-]{3,24}$".

.PARAMETER ApplicationID

The ApplicationID of the ServicePrincipal we are going to use to authenticate with.

.PARAMETER TenantID

The TenantID guid that Application is under.

.PARAMETER CertificateThumprint

The Thumprint of the certificate that is associated with the Application.

.EXAMPLE

C:\PS> Import-Module ".\KeyVault.psm1" -ArgumentList ("<KeyVaultName>", "<ApplicationID>", "<TenantID>", "<Thumbprint>")

#>
[CmdletBinding()]
param
(
	[Parameter(Mandatory=$False, Position = 0)]
	[System.String]
	$VaultName,

	[Parameter(Mandatory=$False, Position = 1)]
	[System.String]
	$ApplicationID,
	
	[Parameter(Mandatory=$False, Position = 2)]
	[System.String]
	$TenantID,

	[Parameter(Mandatory=$False, Position = 3)]
	[System.String]
	$CertificateThumprint
)

if (![System.String]::IsNullOrWhiteSpace($VaultName))
{
	$Script:VaultName = $VaultName
}
else
{
	$Script:VaultName = "default"
}

if (![System.String]::IsNullOrWhiteSpace($ApplicationID) -and 
	![System.String]::IsNullOrWhiteSpace($TenantID) -and 
	![System.String]::IsNullOrWhiteSpace($CertificateThumprint))
{
	Import-Module Azure -ErrorAction Stop
	Login-AzureRmAccount -ServicePrincipal -TenantId $TenantID -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumprint
}

function Get-KeyVaultKey
{
	<#
	.SYNOPSIS
	
	Retrieves a specified Key from a KeyVault.

	.DESCRIPTION

	Retrieves a specified Key from KeyVault using the Azure PowerShell Modules and wraps
	the function up to provide an easier call. 

	.PARAMETER Name

	The Name of the Key in the selected vault we want to retrieve.

	.PARAMETER Version

	The Version of the Key we want, this is an optional field. The default Version
	is the latest one in KeyVault.

	.PARAMETER VaultName

	The Name of the KeyVault you want to retrieve the key from. This parameter is optional,
	it will default to the $Script:VaultName parameter. Azure specifies that a KeyVault name
	must match this regex "^[a-zA-Z0-9-]{3,24}$".

	.EXAMPLE

	Retrieves the latest version of the Key.
	
	C:\PS> Get-KeyVaultKey "KeyName"

	.EXAMPLE
	
	Retrieves the specific version of the Key.

	C:\PS> Get-KeyVaultKey "KeyName" "KeyVersion"

	.EXAMPLE

	Retrieves the latest version of the Key from a different KeyVault than what was passed
	from the script parameters.

	C:\PS> Get-KeyVaultKey -Name "KeyName" -VaultName "VaultName"
	#>
	param
	(
		[Parameter(Mandatory=$True, Position = 0)]
		[ValidateLength(1,127)]
		[System.String]
		$Name,

		[Parameter(ParameterSetName = "Version", Mandatory=$False, Position = 1)]
		[System.String]
		$Version,

		[Parameter(Mandatory=$False, Position = 2)]
		[ValidatePattern("^[a-zA-Z0-9-]{3,24}$")]
		[System.String]
		$VaultName = $Script:VaultName
	)


	switch ($PsCmdlet.ParameterSetName)
	{
		"Version" 
		{ 
			$keyInformation = Get-AzureKeyVaultKey -VaultName $VaultName -Name $Name -Version $Version
		}
		default
		{
			$keyInformation = Get-AzureKeyVaultKey -VaultName $VaultName -Name $Name
		}
	}
	return $keyInformation
}

function Get-KeyVaultSecret
{
	<#
	.SYNOPSIS
	
	Retrieves a specified secret from a KeyVault.

	.DESCRIPTION

	Retrieves a specified secret from KeyVault using the Azure PowerShell Modules and wraps
	the function up to provide an easier call. 

	.PARAMETER VaultUri

	The Name of the secret in the selected vault we want to retrieve. The assumption is the
	URI is formatted as such "Vault://SecretName/SecretVersion", if it does not match this
	pattern we assume the secret is the VaultUri parameter.

	.PARAMETER VaultName

	The Name of the KeyVault you want to retrieve the secret from. This parameter is optional,
	it will default to the $Script:VaultName parameter. Azure specifies that a KeyVault name
	must match this regex "^[a-zA-Z0-9-]{3,24}$".

	.EXAMPLE

	Retrieves the latest version of the secret.
	
	C:\PS> Get-KeyVaultSecret "VaultUri"

	.EXAMPLE

	Retrieves the latest version of the secret from a different KeyVault than what was passed
	from the script parameters.

	C:\PS> Get-KeyVaultSecret -VaultUri "Vault://SecretName/SecretVersion" -VaultName "VaultName"
	#>
	param
	(
		[Parameter(Mandatory=$True, Position = 0)]
		[System.String]
		$VaultUri,

		[Parameter(Mandatory=$False, Position = 1)]
		[ValidatePattern("^[a-zA-Z0-9-]{3,24}$")]
		[System.String]
		$VaultName = $Script:VaultName
	)

	# For Mock secrets
		if($VaultUri -ilike 'SECRET::')
		{
			return $VaultUri -ireplace 'SECRET::', ''
		}

	if (!(Test-ValidKeyVaultUri -VaultUri $VaultUri))
	{
		return $VaultUri
	}
	else
	{		
		[System.Uri]$Uri = [System.Uri]::new($VaultUri)

		$secretName = $Uri.Segments[1]

		if ($Uri.Segments.Count -ge 3)
		{
			$secretInformation = Get-AzureKeyVaultSecret -VaultName $VaultName -Name $secretName -Version $Uri.Segments[2]
		}
		else
		{
			$secretInformation = Get-AzureKeyVaultSecret -VaultName $VaultName -Name $secretName
		}

		return $secretInformation.SecretValueText
	}
}

function Test-ValidKeyVaultUri
{
	param
	(
		[Parameter(Mandatory=$True, Position = 0)]
		[System.String]
		$VaultUri
	)

	if (![System.Uri]::IsWellFormedUriString($VaultUri, [System.UriKind]::Absolute))
	{
		# Check for mock secret
		if($VaultUri -ilike 'SECRET::')
		{
			return $true
		}

		return $false
	}

	[System.Uri]$Uri = [System.Uri]::new($VaultUri)

	if ($Uri.Scheme -ne "vault")
	{
		return $false
	}

	return $true
}
# SIG # Begin signature block
# MIIjgwYJKoZIhvcNAQcCoIIjdDCCI3ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDiTvF/dxXLam2V
# ehdT1UWqS8VgAmVIOfte41UtyrumVaCCDYEwggX/MIID56ADAgECAhMzAAACUosz
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgaTD+5MoH
# GtVU42AimvvvdJ3ZMniFd5QDIJFbgkKYB4IwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQDCBrBALxo/ILK4qq7J/ujhxsA6esdGpazaAbgm9lmI
# tmOQfJ9uTWkAIq26GGOTjG5BFkiVVPpnXZ2O5ZjrepaeXcV1QVHtnp3yppJfTeVa
# 6O7YBBkrZBQz2W0Oi6LRJ11RkjRpE8ETYlZjVxvteRjE9bNPEplpGiHyCRU0kuUA
# gbtyFnEgncKtQ+Wyc6KlVj3RFBYy42TFPgeP7DBFaIgl0Phw8bNr0CERVP9UK2s6
# YIzMy2W5ogzekPxsjSOShdK/Aifcpgh7wcHkaQAcEUAkdbT5gFxc0L+Xpcwh9sdM
# 87ZpcgyW8onI2+eBbWgiO91DhEeYL7vfNW4u6F9+I8anoYIS4jCCEt4GCisGAQQB
# gjcDAwExghLOMIISygYJKoZIhvcNAQcCoIISuzCCErcCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIChLdv6SnrawEm1dDW8Ry3f0WPJt/4VXxlu8LfDI
# sEucAgZhkuF1F7AYEzIwMjExMjAxMDgzODA5Ljg1MVowBIACAfSggdCkgc0wgcox
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
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg0i+gIt9ddamj
# +RvvFqHUmLluMIvcp7ZVHBy1SOObE08wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCCT7lzHo4slUIxfEGp8LXQNik/ecK6vuuGWIcmBrrsnpjCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABUjBLXYms5nBHAAAAAAFS
# MCIEIHeQFLa97+j/941vHPEqMyS/U9VWXPPUeIs6wIzslwyuMA0GCSqGSIb3DQEB
# CwUABIIBAHt67/RpP2hTdLggjHlQK/w2fnOz7RtBWL125j/vHErokslFbDxskrm/
# QHAXaMEII8x2HpM/IcnQDo6kPQl7cAWVteHb2PBE77mgtP6zStJR1eP7Cpkm991t
# mXC5xTSpfkGXTROOQXz3yeIz2ODdFJ//g1aDZPwWn8SV37gBY3/pQxcWCRlOMCKv
# czjQzx8QoKaiPZEOkKItIqgDZFepk36HeslruYAksJ5WS55oXGUuS2G+vywAQyxC
# b02+5RasN4KZ8/UW5ndbs8baFuFGMVRAprLGQVHHf/zcH9l8U29MzeijHYo+OfPF
# MMgWtxuhtGYl52KjmmSx4c5ToCXkClk=
# SIG # End signature block
