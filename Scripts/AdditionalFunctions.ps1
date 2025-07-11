# Forces ScriptSetup is called before this script
if(!(Get-Variable -Name LoadedScriptSetup -Scope Script -ErrorAction SilentlyContinue))
{
	throw 'ScriptSetup.ps1 not loaded'
}

<#
	.SYNPOSIS 
	Converts a uri to point to localhost
#>
function ConvertTo-LocalHost
{
	param
	(
		[ValidateNotNull()]
		[uri]
		$OriginalUri       
	)

	$uriBuilder = New-Object 'System.UriBuilder' -ArgumentList ($OriginalUri)
	$uriBuilder.Host = 'localhost'
	return $uriBuilder.ToString()
}

<#
	.SYNPOSIS 
	Updates the given reference based on MR.ForceLocalHost
#>
function Update-ForceLocalHost
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$ForceLocalHostReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.ForceLocalHost' -UpdateObject:($ForceLocalHostReference) -UpdateObjectName 'ForceLocalHost' -IsBoolean
}

<#
	.SYNPOSIS 
	Updates the given reference based on MR.EnforceEncryption
#>
function Update-EnforceEncryption
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$EnforceEncryptionReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.EnforceEncryption' -UpdateObject:($EnforceEncryptionReference) -UpdateObjectName 'EnforceEncryption' -IsBoolean
}

<#
	.SYNPOSIS 
	Updates the given reference based on MR.DDMData
#>
function Update-DataMartData
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$DDMDataReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDMData' -UpdateObject:($DDMDataReference) -UpdateObjectName 'DDMData'
}

<#
	.SYNPOSIS 
	Updates the settings required for data mart access
#>
function Update-DataMartDataAccess
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$MRDefaultValuesReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.Database' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'DDMDatabaseName' 
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.DbServer' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'DDMSqlServerName' 
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.SqlUser' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'DDMSqlUserName' 
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.DataAccess.SqlPwd' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'DDMSqlUserPassword' -HideValue
	# Runtime user
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.Runtime.DataAccess.SqlUser' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'DDMSqlRuntimeUserName' 
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.DDM.Runtime.DataAccess.SqlPwd' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'DDMSqlRuntimeUserPassword' -HideValue
}

<#
	.SYNPOSIS 
	Updates the settings required for AX database access
#>
function Update-AXDataAccess
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$MRDefaultValuesReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.Database' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXDatabaseName'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.DbServer' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AosSqlServerName'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.SqlUser' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXSqlUserName'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.DataAccess.SqlPwd' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXSqlUserPassword' -HideValue
	# Runtime user
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.Runtime.DataAccess.SqlUser' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXSqlRuntimeUserName'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AX.Runtime.DataAccess.SqlPwd' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXSqlRuntimeUserPassword' -HideValue
}

<#
	.SYNPOSIS 
	Updates the settings needed for authentication with AOS or AAD
#>
function Update-AXAuthenticationSettings
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$MRDefaultValuesReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.CsuClientCertThumbprint' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXCertThumbprint'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AADMetadataLocationFormat' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXAADMetadataLocationFormat'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AADTenantId' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXAADTenantId'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.Realm' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXFederationRealm'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AcsTokenIssuer' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXTokenIssuer'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AADGraphApiCertThumbprint' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXAADGraphApiCertThumbprint'
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AADGraphApiResource' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXAADGraphApiResource'
}

<#
	.SYNPOSIS 
	Updates the Ax SSL Cert Thumbprint 
#>
function Update-AXSslCertThumbprint
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$MRDefaultValuesReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AXSslCertThumbprint' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AXSslCertThumbprint' 
}

<#
	.SYNPOSIS 
	Updates the application service server name for SOAP and non-SOAP WCF communications
#>
function Update-ServerName
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$MRDefaultValuesReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.AOSWebSiteName' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AosWebsiteName' -Mandatory
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.ServicesUrl' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'MRNonSoapApplicationServerName' -Mandatory
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.SoapServicesUrl' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'MRApplicationServerName' -Mandatory
	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.SoapServicesUrl' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'AosServerName' -Mandatory
}

<#
	.SYNPOSIS 
	Updates the URL schema used for non-soap services
#>
function Update-UrlSchema
{
	Param
	(
		[PSCustomObject]
		[ValidateNotNull()]
		$Settings,

		[ref]
		$MRDefaultValuesReference
	)

	Update-ValueFromConfig -Settings $Settings -PropertyName 'MR.UrlSchema' -MRDefaultValues:($MRDefaultValuesReference) -MRDefaultValueName 'UrlSchema' 
}

<#
	.SYNPOSIS 
	Updates the application server name to be localhost if desired
#>
function Set-ApplicationServerName
{
	Param
	(
		[ref]
		$MRDefaultValuesReference,

		[switch]
		$ForceLocalHost
	)

	if($ForceLocalHost)
	{
		if($MRDefaultValuesReference.Value.ContainsKey('MRApplicationServerName'))
		{
			$MRDefaultValuesReference.Value.MRApplicationServerName = ConvertTo-LocalHost $MRDefaultValuesReference.Value.MRApplicationServerName
			$MRDefaultValuesReference.Value.MRNonSoapApplicationServerName = ConvertTo-LocalHost $MRDefaultValuesReference.Value.MRNonSoapApplicationServerName
		}
		else
		{
			# This assumes MRDeploy module has already been imported.
			$MRDefaultValuesReference.Value.MRApplicationServerName = ConvertTo-LocalHost (Get-MRDefaultValues).MRApplicationServerName
			$MRDefaultValuesReference.Value.MRNonSoapApplicationServerName = ConvertTo-LocalHost (Get-MRDefaultValues).MRNonSoapApplicationServerName
		}
	}
}

<#
	.SYNPOSIS 
	Updates the AX server name to be localhost if desired
#>
function Set-AXServerName
{
	Param
	(
		[ref]
		$MRDefaultValuesReference,

		[switch]
		$ForceLocalHost
	)

	if($ForceLocalHost)
	{
		if($MRDefaultValuesReference.Value.ContainsKey('AosServerName'))
		{
			$MRDefaultValuesReference.Value.AosServerName = ConvertTo-LocalHost $MRDefaultValuesReference.Value.AosServerName
		}
		else
		{
			# This assumes MRDeploy module has already been imported.
			$MRDefaultValuesReference.Value.AosServerName = ConvertTo-LocalHost (Get-MRDefaultValues).AosServerName
		}
	}
}
# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8LsZEJdcyQjIp
# go4klFn1qlScb/yT5g7N3BwGCh6qkqCCDYEwggX/MIID56ADAgECAhMzAAACUosz
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWjCCFVYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg1D4iwyfk
# JYFQ2pXgECFjrGSqbP4ekHSMYh+tVPvQBK8wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCv/xNVzu0FzCF6vAEEMbN4pnlfg0PTuBkolu0Zs6lW
# 7HMzsOzvMcZu/XQOx11TrmxUdmdQMDnTwFBVk74lHMeg3IOsanAFoC1QuY5fXSp4
# C31bJtDZSdIK9ZX09MOJhfHv1F7ErOEihnonPs8BqkHC7V27NZKJoLsmpmJXs3Kx
# Uq0bI0CtddLF31guM5EyGCFLxUFHlHS8kfvOkp5YgG7pNkne5jpuJWdVWUgGnbQD
# A6wrlQPys/zgHS/hXWJ4+iPTEOMbRWVAJres/4+qw0yCTXGZhTizrbB9QXaKK8N4
# I9EqtL8qz6P0usG5Q7CU+kjd71RVeqiLSX6uYjZqMErwoYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVAGCyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIHQiMnl0cRje03AG/u4hMy/sJ1DIcESCeegHYLr7
# GHibAgZhktY0+ZMYEjIwMjExMjAxMDgzNzA4Ljc4WjAEgAIB9KCB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2Wggg48MIIE8TCCA9mgAwIBAgITMwAAAUtPsqZI1eTCUQAAAAABSzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MDExMTIxODI1NTlaFw0yMjAyMTExODI1NTlaMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUzNEYtOURE
# QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKE2elDHdi4mv+K+hs+gu2lD16BQWXxM
# d1ZnpIAogl20/cvbgPf93reiaaaNmMLKtCb6P/W0cMDCNAa47Bi+fv15w8JB8AH3
# UmcSn/A/gEwXZJfIx/yT1HzhG2Eh18Yc9dNarOkIJ81aiVURxRWbwB3+vUuuKRE7
# 7goqjqyUNAkqyAoCl8FT/0ntG52+HDWsRDDQ2TUFEZaOsinv+5ahQh9HityXpTW6
# 06JgiicLzs8+kAlBcZGwN0qdUUXg2la8yLJ66Syfm3863DPzawaWd78c1CmYzOKB
# Hxxnx5cQMkk0hnGi/1YAcePbyBQTb0PyK8BPvTqKHG9O/nRljxbnW7ECAwEAAaOC
# ARswggEXMB0GA1UdDgQWBBRSqmp+0BKW57orct4+VNOfTUrrxjAfBgNVHSMEGDAW
# gBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0Ff
# MjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEw
# LTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4IBAQAW2rnVlz87UB8kri0QHY2vxsYRUPmpDyXyBchAysxl
# i110cf5waKqAX/gaa+Y9+XkUBiH6B//xh3erj+IPb4rgu0luz/e/qanIGXWZDi+6
# wrrl0DKlaaJPVbcWJeOyYIiSNIMOwosUFgfnIYWc0U4QyAv47u7iiwfjZ/zSdzZZ
# 2dlXr469bTflc9Xpm21QF8VYd0htSR04bU7afjImbXQ59pwi1nTx/OAwyoT5/9JO
# BVY0IdtHYRipNZrKsY/r2MzC1UP0EYZNa2LVeOm8TrIp07wf2e5GLcv4LqNie19o
# SYFNudMURX6RHHUI1ylJv2izzoIBR6FlTVpHNDoJD+mPMIIGcTCCBFmgAwIBAgIK
# YQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0
# NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX7
# 7XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM
# 1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHP
# k0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3Ws
# vYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw
# 6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHi
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVt
# VTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGS
# MIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4y
# IB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAu
# IB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+
# zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKK
# dsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/Uv
# eYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4z
# u2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHim
# bdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlX
# dqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHh
# AN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A
# +xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdC
# osnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42ne
# V8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nf
# j950iEkSoYICzjCCAjcCAQEwgfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9w
# ZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODItRTM0Ri05RERB
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYF
# Kw4DAhoDFQCROjP3t+x4fE05RJDk79sFVIX57qCBgzCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5VEa6jAiGA8yMDIx
# MTIwMTA1NDkzMFoYDzIwMjExMjAyMDU0OTMwWjB3MD0GCisGAQQBhFkKBAExLzAt
# MAoCBQDlURrqAgEAMAoCAQACAhhuAgH/MAcCAQACAhEoMAoCBQDlUmxqAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAiuT5F7GbxsydL536JhNY6BXHcghfoySa
# +Xk0qvhfHEbaS1oWkin2PjsTCesQmaI5z7CrRYRZT6gUyFv+Z63bUDXtvl44v9ws
# FDhMRcZeoKzG4uMZU7Nfkd/5wuRkFC/k6g594nirGxzbhZ1tcaIPbiZNjUb3AASG
# HVZIwmYhkaUxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAUtPsqZI1eTCUQAAAAABSzANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBaPSxmDaqn
# /xVNXpcTd5z8Z/R8/sp+Yj7JjeemC9kEADCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIGv27oQieexlgS2z8WP+sgW/RhlbXKeFco4/aFU9RTkjMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFLT7KmSNXkwlEAAAAA
# AUswIgQg+fxYEn4DOdKjXwvIlMHxdqzUXBKQKkRhQEwKg2CfXSkwDQYJKoZIhvcN
# AQELBQAEggEAPB6g3ulU4ZaWXosP2YnHyWJktdxUfAGBqoOO9wZ6K+nFS/ufG9Bd
# uhJXADR+AFpko1swIMUdW+kK6QyNOV12QC6JaIfMx1s2jFWtU84hLftO4dmQSEqo
# peczAgYqG3GhvFlvI/PwjJjbZObMBN2e+un+UaKH/d76M07hM5A4MtC2TzTr8m/w
# VifpLfpnqpFwpE2xoum8G5GzL+sQFBIowUhQJRomouSqnmWL/l3GyAR3la7g80TH
# X71sTFETu9nMwlb2jBq6oD7ncAT4Uou2q7+oSaWmUpS9Im+cmTlU1ScMSwH+Vbct
# 8XfmE7LaPt/lOns6487jtSd/VpIcVFJvkg==
# SIG # End signature block
