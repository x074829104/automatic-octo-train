# ---------------------------------
# Function definitions
# ---------------------------------
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
           if ($null -ne $reader)
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
           if ($null -ne $writer)
           {
               $writer.dispose()
           }
        }
    }
}

function New-SelfSignedCertificateEx
{
<#
.Synopsis
    This cmdlet generates a self-signed certificate.
.Description
    This cmdlet generates a self-signed certificate with the required data.
.Parameter Subject
    Specifies the certificate subject in a X500 distinguished name format.
    Example: CN=Test Cert, OU=Sandbox
.Parameter NotBefore
    Specifies the date and time when the certificate become valid. By default previous day
    date is used.
.Parameter NotAfter
    Specifies the date and time when the certificate expires. By default, the certificate is
    valid for 1 year.
.Parameter SerialNumber
    Specifies the desired serial number in a hex format.
    Example: 01a4ff2
.Parameter ProviderName
    Specifies the Cryptography Service Provider (CSP) name. You can use either legacy CSP
    and Key Storage Providers (KSP). By default "Microsoft Enhanced Cryptographic Provider v1.0"
    CSP is used.
.Parameter AlgorithmName
    Specifies the public key algorithm. By default RSA algorithm is used. RSA is the only
    algorithm supported by legacy CSPs. With key storage providers (KSP) you can use CNG
    algorithms, like ECDH. For CNG algorithms you must use full name:
    ECDH_P256
    ECDH_P384
    ECDH_P521

    In addition, KeyLength parameter must be specified explicitly when non-RSA algorithm is used.
.Parameter KeyLength
    Specifies the key length to generate. By default 2048-bit key is generated.
.Parameter KeySpec
    Specifies the public key operations type. The possible values are: Exchange and Signature.
    Default value is Exchange.
.Parameter EnhancedKeyUsage
    Specifies the intended uses of the public key contained in a certificate. You can
    specify either, EKU friendly name (for example 'Server Authentication') or
    object identifier (OID) value (for example '1.3.6.1.5.5.7.3.1').
.Parameter KeyUsages
    Specifies restrictions on the operations that can be performed by the public key contained in the certificate.
    Possible values (and their respective integer values to make bitwise operations) are:
    EncipherOnly
    CrlSign
    KeyCertSign
    KeyAgreement
    DataEncipherment
    KeyEncipherment
    NonRepudiation
    DigitalSignature
    DecipherOnly

    you can combine key usages values by using bitwise OR operation. when combining multiple
    flags, they must be enclosed in quotes and separated by a comma character. For example,
    to combine KeyEncipherment and DigitalSignature flags you should type:
    "KeyEncipherment, DigitalSignature".

    If the certificate is CA certificate (see IsCA parameter), key usages extension is generated
    automatically with the following key usages: Certificate Signing, Off-line CRL Signing, CRL Signing.
.Parameter SubjectAlternativeName
    Specifies alternative names for the subject. Unlike Subject field, this extension
    allows to specify more than one name. Also, multiple types of alternative names
    are supported. The cmdlet supports the following SAN types:
    RFC822 Name
    IP address (both, IPv4 and IPv6)
    Guid
    Directory name
    DNS name
.Parameter IsCA
    Specifies whether the certificate is CA (IsCA = $true) or end entity (IsCA = $false)
    certificate. If this parameter is set to $false, PathLength parameter is ignored.
    Basic Constraints extension is marked as critical.
.PathLength
    Specifies the number of additional CA certificates in the chain under this certificate. If
    PathLength parameter is set to zero, then no additional (subordinate) CA certificates are
    permitted under this CA.
.CustomExtension
    Specifies the custom extension to include to a self-signed certificate. This parameter
    must not be used to specify the extension that is supported via other parameters. In order
    to use this parameter, the extension must be formed in a collection of initialized
    System.Security.Cryptography.X509Certificates.X509Extension objects.
.Parameter SignatureAlgorithm
    Specifies signature algorithm used to sign the certificate. By default 'SHA1'
    algorithm is used.
.Parameter FriendlyName
    Specifies friendly name for the certificate.
.Parameter StoreLocation
    Specifies the store location to store self-signed certificate. Possible values are:
    'CurrentUser' and 'LocalMachine'. 'CurrentUser' store is intended for user certificates
    and computer (as well as CA) certificates must be stored in 'LocalMachine' store.
.Parameter StoreName
    Specifies the container name in the certificate store. Possible container names are:
    AddressBook
    AuthRoot
    CertificateAuthority
    Disallowed
    My
    Root
    TrustedPeople
    TrustedPublisher
.Parameter Path
    Specifies the path to a PFX file to export a self-signed certificate.
.Parameter Password
    Specifies the password for PFX file.
.Parameter AllowSMIME
    Enables Secure/Multipurpose Internet Mail Extensions for the certificate.
.Parameter Exportable
    Marks private key as exportable. Smart card providers usually do not allow
    exportable keys.
.Example
    New-SelfsignedCertificateEx -Subject "CN=Test Code Signing" -EKU "Code Signing" -KeySpec "Signature" `
    -KeyUsage "DigitalSignature" -FriendlyName "Test code signing" -NotAfter [datetime]::now.AddYears(5)

    Creates a self-signed certificate intended for code signing and which is valid for 5 years. Certificate
    is saved in the Personal store of the current user account.
.Example
    New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
    -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
    [SuppressMessage("Microsoft.Security", "CS002:SecretInNextLine")]
    -AllowSMIME -Path C:\test\ssl.pfx -Password (ConvertTo-SecureString XXXXXXX -AsPlainText -Force) -Exportable `
    -StoreLocation "LocalMachine"

    Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
    certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
    so you can export the certificate with a associated private key to a file at any time. The certificate
    includes SMIME capabilities.
.Example
    New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
    -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
    -StoreLocation "LocalMachine" -ProviderName "Microsoft Software Key Storae Provider" -AlgorithmName ecdh_256 `
    -KeyLength 256 -SignatureAlgorithm sha256

    Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
    certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
    so you can export the certificate with a associated private key to a file at any time. Certificate uses
    Ellyptic Curve Cryptography (ECC) key algorithm ECDH with 256-bit key. The certificate is signed by using
    SHA256 algorithm.
.Example
    New-SelfsignedCertificateEx -Subject "CN=Test Root CA, OU=Sandbox" -IsCA $true -ProviderName `
    "Microsoft Software Key Storage Provider" -Exportable

    Creates self-signed root CA certificate.
#>
[CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        [datetime]$NotBefore = [DateTime]::Now.AddDays(-1),
        [datetime]$NotAfter = $NotBefore.AddDays(365),
        [string]$SerialNumber,
        [Alias('CSP')]
        [string]$ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0",
        [string]$AlgorithmName = "RSA",
        [int]$KeyLength = 2048,
        [validateSet("Exchange","Signature")]
        [string]$KeySpec = "Exchange",
        [Alias('EKU')]
        [Security.Cryptography.Oid[]]$EnhancedKeyUsage,
        [Alias('KU')]
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage,
        [Alias('SAN')]
        [String[]]$SubjectAlternativeName,
        [bool]$IsCA,
        [int]$PathLength = -1,
        [Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        [string]$SignatureAlgorithm = "SHA1",
        [string]$FriendlyName,
        [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
        [Security.Cryptography.X509Certificates.StoreName]$StoreName = "My",
        [Alias('OutFile','OutPath','Out')]
        [IO.FileInfo]$Path,
        [Security.SecureString]$Password,
        [switch]$AllowSMIME,
        [switch]$Exportable
    )
    $ErrorActionPreference = "Stop"
    if ([Environment]::OSVersion.Version.Major -lt 6)
    {
        $NotSupported = New-Object NotSupportedException -ArgumentList "Windows XP and Windows Server 2003 are not supported!"
        throw $NotSupported
    }
    $ExtensionsToAdd = @()

#region constants
    # contexts
    New-Variable -Name UserContext -Value 0x1 -Option Constant
    New-Variable -Name MachineContext -Value 0x2 -Option Constant
    # encoding
    New-Variable -Name Base64Header -Value 0x0 -Option Constant
    New-Variable -Name Base64 -Value 0x1 -Option Constant
    New-Variable -Name Binary -Value 0x3 -Option Constant
    New-Variable -Name Base64RequestHeader -Value 0x4 -Option Constant
    # SANs
    New-Variable -Name OtherName -Value 0x1 -Option Constant
    New-Variable -Name RFC822Name -Value 0x2 -Option Constant
    New-Variable -Name DNSName -Value 0x3 -Option Constant
    New-Variable -Name DirectoryName -Value 0x5 -Option Constant
    New-Variable -Name URL -Value 0x7 -Option Constant
    New-Variable -Name IPAddress -Value 0x8 -Option Constant
    New-Variable -Name RegisteredID -Value 0x9 -Option Constant
    New-Variable -Name Guid -Value 0xa -Option Constant
    New-Variable -Name UPN -Value 0xb -Option Constant
    # installation options
    New-Variable -Name AllowNone -Value 0x0 -Option Constant
    New-Variable -Name AllowNoOutstandingRequest -Value 0x1 -Option Constant
    New-Variable -Name AllowUntrustedCertificate -Value 0x2 -Option Constant
    New-Variable -Name AllowUntrustedRoot -Value 0x4 -Option Constant
    # PFX export options
    New-Variable -Name PFXExportEEOnly -Value 0x0 -Option Constant
    New-Variable -Name PFXExportChainNoRoot -Value 0x1 -Option Constant
    New-Variable -Name PFXExportChainWithRoot -Value 0x2 -Option Constant
#endregion

#region Subject processing
    # http://msdn.microsoft.com/en-us/library/aa377051(VS.85).aspx
    $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $SubjectDN.Encode($Subject, 0x0)
#endregion

#region Extensions

#region Enhanced Key Usages processing
    if ($EnhancedKeyUsage)
    {
        $OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
        $EnhancedKeyUsage | ForEach-Object {
            $OID = New-Object -ComObject X509Enrollment.CObjectID
            $OID.InitializeFromValue($_.Value)
            # http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
            $OIDs.Add($OID)
        }

        # http://msdn.microsoft.com/en-us/library/aa378132(VS.85).aspx
        $EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
        $EKU.InitializeEncode($OIDs)
        $ExtensionsToAdd += "EKU"
    }
#endregion

#region Key Usages processing
    if ($null -ne $KeyUsage)
    {
        $KU = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $KU.InitializeEncode([int]$KeyUsage)
        $KU.Critical = $true
        $ExtensionsToAdd += "KU"
    }
#endregion

#region Basic Constraints processing
    if ($PSBoundParameters.Keys.Contains("IsCA"))
    {
        # http://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
        $BasicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints
        if (!$IsCA)
        {
            $PathLength = -1
        }

        $BasicConstraints.InitializeEncode($IsCA,$PathLength)
        $BasicConstraints.Critical = $IsCA
        $ExtensionsToAdd += "BasicConstraints"
    }
#endregion

#region SAN processing
    if ($SubjectAlternativeName)
    {
        $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $Names = New-Object -ComObject X509Enrollment.CAlternativeNames
        foreach ($altname in $SubjectAlternativeName)
        {
            $Name = New-Object -ComObject X509Enrollment.CAlternativeName
            if ($altname.Contains("@"))
            {
                $Name.InitializeFromString($RFC822Name,$altname)
            }
            else
            {
                try
                {
                    $Bytes = [Net.IPAddress]::Parse($altname).GetAddressBytes()
                    $Name.InitializeFromRawData($IPAddress,$Base64,[Convert]::ToBase64String($Bytes))
                }
                catch
                {
                    try
                    {
                        $Bytes = [Guid]::Parse($altname).ToByteArray()
                        $Name.InitializeFromRawData($Guid,$Base64,[Convert]::ToBase64String($Bytes))
                    }
                    catch
                    {
                        try
                        {
                            $Bytes = ([Security.Cryptography.X509Certificates.X500DistinguishedName]$altname).RawData
                            $Name.InitializeFromRawData($DirectoryName,$Base64,[Convert]::ToBase64String($Bytes))
                        }
                        catch
                        {
                            $Name.InitializeFromString($DNSName,$altname)
                        }
                    }
                }
            }

            $Names.Add($Name)
        }

        $SAN.InitializeEncode($Names)
        $ExtensionsToAdd += "SAN"
    }
#endregion

#region Custom Extensions
    if ($CustomExtension)
    {
        $count = 0
        foreach ($ext in $CustomExtension)
        {
            # http://msdn.microsoft.com/en-us/library/aa378077(v=vs.85).aspx
            $Extension = New-Object -ComObject X509Enrollment.CX509Extension
            $EOID = New-Object -ComObject X509Enrollment.CObjectId
            $EOID.InitializeFromValue($ext.Oid.Value)
            $EValue = [Convert]::ToBase64String($ext.RawData)
            $Extension.Initialize($EOID,$Base64,$EValue)
            $Extension.Critical = $ext.Critical
            New-Variable -Name ("ext" + $count) -Value $Extension
            $ExtensionsToAdd += ("ext" + $count)
            $count++
        }
    }
#endregion

#endregion

#region Private Key
    # http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
    $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $PrivateKey.ProviderName = $ProviderName
    $AlgID = New-Object -ComObject X509Enrollment.CObjectId
    $AlgID.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value)
    $PrivateKey.Algorithm = $AlgID
    # http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
    $PrivateKey.KeySpec = switch ($KeySpec) {"Exchange" {1}; "Signature" {2}}
    $PrivateKey.Length = $KeyLength
    # key will be stored in current user certificate store
    $PrivateKey.MachineContext = if ($StoreLocation -eq "LocalMachine") { $true} else { $false}

    $PrivateKey.ExportPolicy = if ($Exportable) {1} else {0}
    $PrivateKey.Create()
#endregion

    # http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
    $Cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
    if ($PrivateKey.MachineContext)
    {
        $Cert.InitializeFromPrivateKey($MachineContext,$PrivateKey,"")
    }
    else
    {
        $Cert.InitializeFromPrivateKey($UserContext,$PrivateKey,"")
    }

    $Cert.Subject = $SubjectDN
    $Cert.Issuer = $Cert.Subject
    $Cert.NotBefore = $NotBefore
    $Cert.NotAfter = $NotAfter
    foreach ($Item in $ExtensionsToAdd)
    {
        $Cert.X509Extensions.Add((Get-Variable -Name $Item -ValueOnly))
    }
    if (![string]::IsNullOrEmpty($SerialNumber))
    {
        if ($SerialNumber -match "[^0-9a-fA-F]")
        {
            throw "Invalid serial number specified."
        }

        if ($SerialNumber.Length % 2)
        {
            $SerialNumber = "0" + $SerialNumber
        }

        $Bytes = $SerialNumber -split "(.{2})" | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_,16) }
        $ByteString = [Convert]::ToBase64String($Bytes)
        $Cert.SerialNumber.InvokeSet($ByteString,1)
    }

    if ($AllowSMIME)
    {
        $Cert.SmimeCapabilities = $true
    }

    $SigOID = New-Object -ComObject X509Enrollment.CObjectId
    $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)
    $Cert.SignatureInformation.HashAlgorithm = $SigOID
    # completing certificate request template building
    $Cert.Encode()

    # interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
    $Request = New-Object -ComObject X509Enrollment.CX509enrollment
    $Request.InitializeFromRequest($Cert)
    $Request.CertificateFriendlyName = $FriendlyName
    $endCert = $Request.CreateRequest($Base64)
    $Request.InstallResponse($AllowUntrustedCertificate,$endCert,$Base64,"")
    if (![string]::IsNullOrEmpty($Path) -and ![string]::IsNullOrEmpty($Password))
    {
        $PFXString = $Request.CreatePFX(
            [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
            $PFXExportEEOnly,
            $Base64
        )
        Set-Content -Path $Path -Value ([Convert]::FromBase64String($PFXString)) -Encoding Byte
    }
}

function Invoke-Icacls
{
    <#
        .SYNOPSIS
            Invoke icacls to grant access to the private key of a specified certificate for a specified user.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        # Account to have private key access on the specified certificate
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AccountName = "NT AUTHORITY\NETWORK SERVICE",

        # Thumbprint of certificate to have private key access on
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Thumbprint
    )

    $KeyContainerName = (((Get-ChildItem cert:\LocalMachine\my | Where-Object { $_.thumbprint -like $Thumbprint }).PrivateKey).CspKeyContainerInfo).UniqueKeyContainerName
    $KeyFilePath = Join-Path -Path $Env:ProgramData -ChildPath "Microsoft\Crypto\RSA\MachineKeys" | Join-Path -ChildPath $KeyContainerName

    Write-Host "icacls $KeyFilePath /grant $AccountName`:RX"
    icacls $KeyFilePath /grant $AccountName`:RX *>&1 | Write-Host

    Write-Host "LASTEXITCODE: $LASTEXITCODE"
    if ($LASTEXITCODE -ne 0)
    {
        throw "Could not add $AccountName to private key for certificate $Thumbprint"
    }
}

function New-ComplexSecret
{
    <#
    .Synopsis
      This will generate a new password in Powershell using Special, Uppercase, Lowercase and Numbers.  The max number of characters are currently set to 79.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0,Mandatory = $false)]
        [ValidateRange(5,79)]
        [int]    $Length = 16,
        [switch] $ExcludeSpecialCharacters
    )
    BEGIN {
        $SpecialCharacters = @((33,35) + (36..38) + (42..44) + (60..64) + (91..94))
    }
    PROCESS {
        try {
            if (-not $ExcludeSpecialCharacters) {
                    $Password = -join ((48..57) + (65..90) + (97..122) + $SpecialCharacters | Get-Random -Count $Length | ForEach-Object {[char]$_})
                } else {
                    $Password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count $Length | ForEach-Object {[char]$_})
            }
        } catch {
            Write-Error $_.Exception.Message
        }
    }
    END {
        return $Password
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

# ---------------------------------
# Main body
# ---------------------------------
Write-Host "You MUST provide an Application Id to continue..." -ForegroundColor Green
$ApplicationId = Read-Host -Prompt "Please enter the Application Id"
$CustomerAppCertThumb = $null
$CustomerAppCertSupplied = $false
$CustomerAppCert = $null
if([string]::IsNullOrEmpty($ApplicationId))
{
    Write-Error "You must provide an Application Id to continue..."
    Exit
}
Write-Host ""
$message = 'Do you have an existing certificate for the provided Application Id? [Y/N]'
do {
    $response = Read-Host -Prompt $message
    if ($response -ieq 'y') {
        $CustomerAppCertSupplied = $true
        $CustomerAppCertThumb = Read-Host -Prompt "Please enter the thumbprint for the Application certificate (NOTE: It must already be installed for the local machine)"
    }
} until (($response -ieq 'n') -or ($response -ieq 'y'))

if([string]::IsNullOrEmpty($ApplicationId))
{
    Write-Error "You must provide an Application Id to continue."
    Exit
}

if($true -eq $CustomerAppCertSupplied)
{
    if(Test-Path -Path Cert:\LocalMachine\My\$CustomerAppCertThumb)
    {
        $CustomerAppCert = Get-ChildItem -Path Cert:\LocalMachine\My\$CustomerAppCertThumb
    }
    else
    {
        Write-Error "You must provide a valid thumbprint for the Application certificate installed to the Local Machine."
        Exit
    }
}

# Set Script Location (for the shortcut usage)
Set-Location -Path "C:\DynamicsTools\CleanVHD"

# Stop Batch to free up resources
Stop-Service -Name DynamicsAxBatch -Force

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
$mrAppBinDirectory = "c:\FinancialReporting\Server\ApplicationService\bin"
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

# Define path of VhdCertificates.json file
$vhdCertificatesPath = Join-Path -Path $currentDirectory -ChildPath $vhdCertificatesFileName

# Load certificate info in json object
$certificates = Get-Content $vhdCertificatesPath | Out-String | ConvertFrom-Json

# Loop through the certificates in the file
# Create and install self-signed certificate
# Replace semaphor in config file with certificate thumbprint
# Bind F&O websites to new certs
Import-Module IISAdministration
ForEach ($certificate in $certificates)
{
    $semaphore = $certificate.Semaphore
    $subjectName = $certificate.SubjectName
    $subjectAlternateName = $certificate.SubjectAlternateName

    $signatureAlgorithm = $certificate.SignatureAlgorithm.Replace("RSA", "")
    $publicKey = $certificate.PublicKey
    $keyLength = $certificate.KeyLength
    $dnsNameList = $certificate.DnsNameList
    $dnsNameListSplit = $DnsNameList.Split(",")
    $dnsNameArray = @()
    ForEach ($dnsName in $dnsNameListSplit)
    {
        $dnsNameArray += $dnsName
    }

    Write-Host "Creating self-signed certificate with Subject: $($certificate.SubjectName)"
    
    if ([string]::IsNullOrWhiteSpace($subjectAlternateName))
    {

        if ($subjectName.Contains("DataEncryptionCertificate"))
        {
            $cert = New-SelfSignedCertificate -Subject "$($subjectName)" -CertStoreLocation "Cert:\LocalMachine\My" -KeyExportPolicy Exportable -KeySpec KeyExchange -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm sha256 -NotAfter (Get-Date).AddYears(30) -KeyUsageProperty All -Type Custom -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -KeyUsage @('EncipherOnly', 'CRLSign', 'CertSign', 'KeyAgreement', 'DataEncipherment', 'KeyEncipherment', 'NonRepudiation', 'DigitalSignature', 'DecipherOnly')
            Invoke-Icacls -Thumbprint $cert.Thumbprint
            $thumbprint = $cert.Thumbprint
            $tempPwd = ConvertTo-SecureString -String $(New-ComplexSecret) -AsPlainText -Force
            # Need to add cert to root authority
            Get-ChildItem -Path "cert:\localMachine\my\$thumbprint" | Export-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Password $tempPwd
            Import-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -CertStoreLocation "Cert:\LocalMachine\Root" -Password $tempPwd
            Remove-Item -Path (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Force
        }
        else
        {
            if($semaphore -ieq"[SESSION AUTH CERT THUMBPRINT]")
            {
                $tempPwd = ConvertTo-SecureString -String $(New-ComplexSecret) -AsPlainText -Force
                $cert = New-SelfSignedCertificateEx -Subject "$($subjectName)" -EKU "Server Authentication", "Client Authentication" -Path (Join-Path -Path $currentDirectory -ChildPath "SESSIONAUTHCERTTHUMBPRINT.pfx") -Password $tempPwd -Exportable -StoreLocation "LocalMachine"
                $cert = Get-ChildItem -Path "cert:\localMachine\my" | Where-Object {$_.Subject -ieq "$subjectName"}
                Invoke-Icacls -Thumbprint $cert.Thumbprint
                $thumbprint = $cert.Thumbprint
                # Need to add cert to root authority
                Get-ChildItem -Path "cert:\localMachine\my\$thumbprint" | Export-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Password $tempPwd
                Import-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -CertStoreLocation "Cert:\LocalMachine\Root" -Password $tempPwd
                Remove-Item -Path (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Force
                Remove-Item -Path (Join-Path -Path $currentDirectory -ChildPath "SESSIONAUTHCERTTHUMBPRINT.pfx") -Force
            }
            else
            {
                $cert = New-SelfSignedCertificate -Subject "$($subjectName)" -CertStoreLocation "Cert:\LocalMachine\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength $keyLength -KeyAlgorithm $publicKey -HashAlgorithm $signatureAlgorithm -KeyUsage @('DigitalSignature', 'DataEncipherment', 'KeyEncipherment')
                Invoke-Icacls -Thumbprint $cert.Thumbprint
                $thumbprint = $cert.Thumbprint
                $tempPwd = ConvertTo-SecureString -String $(New-ComplexSecret) -AsPlainText -Force
                # Need to add cert to root authority
                Get-ChildItem -Path "cert:\localMachine\my\$thumbprint" | Export-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Password $tempPwd
                Import-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -CertStoreLocation "Cert:\LocalMachine\Root" -Password $tempPwd
                Remove-Item -Path (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Force

                if($semaphore -ieq "[FAKE ACS CERT THUMBPRINT]")
                {
                    # Update the new offline Fake ACS cert thumbprint in the registry for DevTools
                    if(!(Test-Path -Path 'HKCU:\SOFTWARE\Microsoft\Dynamics\AX7\Development\Configurations'))
                    {
                        New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Dynamics\AX7\Development' -Name 'Configurations' -Force
                        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Dynamics\AX7\Development\Configurations' -Name 'offlineDevCertThumbprint' -Value '' -Type String
                    }
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Dynamics\AX7\Development\Configurations' -Name offlineDevCertThumbprint -Value $cert.Thumbprint
                    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Dynamics\AX7\Development\Configurations' -Name offlineDevCertThumbprint -Value $cert.Thumbprint
                }
            }
        }
    }
    else
    {
        if($semaphore -ieq"[GRAPHAPI and S2S CERT THUMBPRINT]")
        {
            if([string]::IsNullOrEmpty($CustomerAppCertThumb))
            {
                $cert = New-SelfSignedCertificate -Subject "$($subjectName)" -DnsName $dnsNameArray -CertStoreLocation "Cert:\LocalMachine\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength $keyLength -KeyAlgorithm $publicKey -HashAlgorithm $signatureAlgorithm -KeyUsage @('DigitalSignature', 'DataEncipherment', 'KeyEncipherment')
                Invoke-Icacls -Thumbprint $cert.Thumbprint
                $thumbprint = $cert.Thumbprint
                $tempPwd = ConvertTo-SecureString -String $(New-ComplexSecret) -AsPlainText -Force
                # Need to add SSL binding cert to root authority
                Get-ChildItem -Path "cert:\localMachine\my\$thumbprint" | Export-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Password $tempPwd
                Import-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -CertStoreLocation "Cert:\LocalMachine\Root" -Password $tempPwd
                Remove-Item -Path (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Force
            }
            else
            {
                Invoke-Icacls -Thumbprint $CustomerAppCertThumb
            }
        }
        else
        {
            $cert = New-SelfSignedCertificate -Subject "$($subjectName)" -DnsName $dnsNameArray -CertStoreLocation "Cert:\LocalMachine\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength $keyLength -KeyAlgorithm $publicKey -HashAlgorithm $signatureAlgorithm -KeyUsage @('DigitalSignature', 'DataEncipherment', 'KeyEncipherment')
            Invoke-Icacls -Thumbprint $cert.Thumbprint
            $thumbprint = $cert.Thumbprint
            $tempPwd = ConvertTo-SecureString -String $(New-ComplexSecret) -AsPlainText -Force
            # Need to add SSL binding cert to root authority
            Get-ChildItem -Path "cert:\localMachine\my\$thumbprint" | Export-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Password $tempPwd
            Import-PfxCertificate -FilePath (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -CertStoreLocation "Cert:\LocalMachine\Root" -Password $tempPwd
            Remove-Item -Path (Join-Path -Path $currentDirectory -ChildPath "$thumbprint.pfx") -Force
        }
        if($semaphore -ieq "[AOS SSL BINDING and CSU CERT THUMBPRINT]")
        {
            # Set SSL Binding Cert to F&O Websites
            $binding = Get-WebBinding -Name AOSService -Protocol "https"
            $binding.AddSslCertificate($cert.GetCertHashString(), "my")
        }
        if($semaphore -ieq "[RETAILSERVICEACCOUNT CERT THUMBPRINT]")
        {
            # Set SSL Binding Cert to F&O Retail Websites
            # $binding = Get-WebBinding -Name RetailCloudPos -Protocol "https"
            # $binding.AddSslCertificate($cert.GetCertHashString(), "my")
            # $binding = Get-WebBinding -Name RetailServer -Protocol "https"
            # $binding.AddSslCertificate($cert.GetCertHashString(), "my")
            Write-Host "Retail site is deprecated."
        }
    }

    if ($null -ne $cert -and (-not([string]::IsNullOrWhiteSpace($cert.Thumbprint))))
    {
        # Find semaphore in the config files and replace with the thumbprint
        if(-not ([string]::IsNullOrEmpty($CustomerAppCertThumb)))
        {
            
            Replace-StringInFile -filePath $webConfigWorkingPath -findString "[GRAPHAPI and S2S CERT THUMBPRINT]" -replaceString $CustomerAppCertThumb
            Replace-StringInFile -filePath $wifConfigWorkingPath -findString "[GRAPHAPI and S2S CERT THUMBPRINT]" -replaceString $CustomerAppCertThumb
            Replace-StringInFile -filePath $wifServicesConfigWorkingPath -findString "[GRAPHAPI and S2S CERT THUMBPRINT]" -replaceString $CustomerAppCertThumb
            Replace-StringInFile -filePath $mrServiceHostExeWorkingPath -findString "[GRAPHAPI and S2S CERT THUMBPRINT]" -replaceString $CustomerAppCertThumb
            Replace-StringInFile -filePath $mrServiceHostConnectionsWorkingPath -findString "[GRAPHAPI and S2S CERT THUMBPRINT]" -replaceString $CustomerAppCertThumb
            Replace-StringInFile -filePath $mrServiceHostSettingsWorkingPath -findString "[GRAPHAPI and S2S CERT THUMBPRINT]" -replaceString $CustomerAppCertThumb
        }
        
        Replace-StringInFile -filePath $webConfigWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        Replace-StringInFile -filePath $wifConfigWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        Replace-StringInFile -filePath $wifServicesConfigWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        Replace-StringInFile -filePath $mrServiceHostExeWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        Replace-StringInFile -filePath $mrServiceHostConnectionsWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        Replace-StringInFile -filePath $mrServiceHostSettingsWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        # Replace-StringInFile -filePath $ssrsPVMConfigXmlWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        # Replace-StringInFile -filePath $commerceConfigWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        Replace-StringInFile -filePath $mrDeployConfigWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint

        # Replace-StringInFile -filePath $retailWebConfigWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint
        # Replace-StringInFile -filePath $retailcertauthWorkingPath -findString $certificate.Semaphore -replaceString $cert.Thumbprint

        #Replacing APP ID with provided value
        Replace-StringInFile -filePath $webConfigWorkingPath -findString "[APPLICATIONID]" -replaceString $ApplicationId
        Replace-StringInFile -filePath $wifConfigWorkingPath -findString "[APPLICATIONID]" -replaceString $ApplicationId
        Replace-StringInFile -filePath $wifServicesConfigWorkingPath -findString "[APPLICATIONID]" -replaceString $ApplicationId
        Replace-StringInFile -filePath $mrServiceHostSettingsWorkingPath -findString "[APPLICATIONID]" -replaceString $ApplicationId
    }
}

# Reset all SQL passwords in SQL and web.config
$sqlDbCred = New-ComplexSecret -Length 16 -ExcludeSpecialCharacters
# Will need to decrypt the web.config to get the SQL user credentials, after this

Replace-StringInFile -filePath $webConfigWorkingPath -findString "[AOSDBCRED]" -replaceString "$sqlDbCred"
# Replace-StringInFile -filePath $retailWebConfigWorkingPath -findString "[AOSDBCRED]" -replaceString "$sqlDbCred"
$MRUserPassword = $sqlDbCred 
$AOSUserPassword = $sqlDbCred

# Replace SQL users
Import-Module SQLServer -DisableNameChecking
$sqlSrv = New-Object Microsoft.SqlServer.Management.Smo.Server localhost
$sqlSrv.Logins | Where-Object{$_.Name -ilike 'ax*' -or $_.Name -ilike 'aos*' -or $_.Name -ilike 'mr*'} | ForEach-Object{
    $_.ChangePassword($sqlDbCred);
}

# Collect config values for MR config reset
[xml]$webConfigContent = Get-Content -Path $webConfigWorkingPath
$AOSDatabaseName = ($webConfigContent.configuration.appSettings.add | Where-Object {$_.key -eq "DataAccess.Database"}).Value
$AOSUser = ($webConfigContent.configuration.appSettings.add | Where-Object {$_.key -eq "DataAccess.AxAdminSqlUser"}).Value
$MRDatabaseName = "ManagementReporter"
$MRServer = "localhost"
$MRUser = "MRUser"

# Decryption utility
$encryptionToolPath = Join-Path -Path $webRootDirectory -ChildPath "bin\Microsoft.Dynamics.AX.Framework.ConfigEncryptor.exe"
# Encrypt the web.config file
Set-RetailWebConfigEncryption $retailworkingDirectory "Encrypt"
Start-Process -FilePath $encryptionToolPath -ArgumentList @("-encrypt", $webConfigWorkingPath) -Wait
# Start-Process -FilePath $encryptionToolPath -ArgumentList @("-encrypt", $retailWebConfigWorkingPath) -Wait

# Need to copy all config files from working to live locations and restart services
Copy-Item -Path $webConfigWorkingPath -Destination $webRootDirectory -Force
Copy-Item -Path $wifConfigWorkingPath -Destination $webRootDirectory -Force
Copy-Item -Path $wifServicesConfigWorkingPath -Destination $webRootDirectory -Force

# Copy-Item -Path $ssrsPVMConfigXmlWorkingPath -Destination $ssrsRootDirectory -Force
# Copy-Item -Path $commerceConfigWorkingPath -Destination $commerceRootDirectory -Force

# Copy-Item -Path $retailWebConfigWorkingPath -Destination $RetailRootDirectory -Force
# Copy-Item -Path $retailcertauthWorkingPath -Destination $RetailAuthRootDirectory -Force

# Restart IIS to accept changes to binding
& iisreset /restart

#Stop MR Service
Stop-Service -Name MR2012ProcessService -Force

# Copy over all MR configs to replace existing
Copy-Item -Path $mrServiceHostExeWorkingPath -Destination $mrServiceDirectory -Force
Copy-Item -Path $mrServiceHostExeWorkingPath -Destination $mrAppBinDirectory -Force
Copy-Item -Path $mrServiceHostSettingsWorkingPath -Destination $mrServiceDirectory -Force
Copy-Item -Path $mrServiceHostSettingsWorkingPath -Destination $mrAppBinDirectory -Force
Copy-Item -Path $mrDeployConfigWorkingPath -Destination $mrConsoleDirectory -Force

# Update ServiceDrive variable for MR
Set-Variable -Name ServiceDrive -Value "C:"
$env:SERVICEDRIVE = "C:"

# Update the MR Connections.config
& C:\DynamicsTools\CleanVHD\Write-MRConnections.ps1 -MRDatabaseName $MRDatabaseName -MRServer $MRServer -MRRuntimeUser $MRUser -MRRuntimeUserPassword $MRUserPassword

# Update the MR config in the Database and set the new encryption cert
& C:\DynamicsTools\CleanVHD\Scripts\Update\ConfigureMRDatabase.ps1 -NewAosDatabaseName $AOSDatabaseName `
 -NewAosDatabaseServerName localhost -NewMRDatabaseName $MRDatabaseName -NewMRDatabaseServerName $MRServer `
 -NewAxAdminUserName $AOSUser -NewAxAdminUserPassword $AOSUserPassword -NewAxMRRuntimeUserName $MRUser `
 -NewAxMRRuntimeUserPassword $MRUserPassword -NewMRAdminUserName $MRUser -NewMRAdminUserPassword $MRUserPassword `
 -NewMRRuntimeUserName $MRUser -NewMRRuntimeUserPassword $MRUserPassword

# Start Batch & MR Service to take effect
Start-Service -Name MR2012ProcessService
Start-Service -Name DynamicsAxBatch

# Final Clean up
Remove-Item -Path $workingDirectory -Recurse
# Remove-Item -Path $retailworkingDirectory -Recurse

Write-Host " "
Write-Host "New self signed certificates have been generated the configuration files updated and services restarted."
Write-Host " "
Write-Host "You can now close this window, you may still need to reset your tenant and export the self signed certificates based on your scenario."
Write-Host " "
# SIG # Begin signature block
# MIIr5AYJKoZIhvcNAQcCoIIr1TCCK9ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB4vbkkm5pJUTlr
# fO272vTFQf+JRZrKRS0xoSA4tk2phKCCEW4wggh+MIIHZqADAgECAhM2AAAB33OB
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
# fiK9+iVTLdD1h/SxyxDpZMtimb4CgJQlMYIZzDCCGcgCAQEwWDBBMRMwEQYKCZIm
# iZPyLGQBGRYDR0JMMRMwEQYKCZImiZPyLGQBGRYDQU1FMRUwEwYDVQQDEwxBTUUg
# Q1MgQ0EgMDECEzYAAAHfc4GXFr4y/Q0AAgAAAd8wDQYJYIZIAWUDBAIBBQCgga4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIE9ZMF43YQ+uS5mel6CO0JLCluue9Ui4
# RKQbevgzKLv5MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYA
# dKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEA
# bpnCcSQyaWR+UkpB8YJPxKRY/t67YFhCuuXh/Kb35lVXo/GXTi5Y5J/mOoyENGxj
# BGvcd/Vc6+LPaBe5gdAhD1szNc4hbGw0UskOT6pm2ycgRlcjCOmg1NNY5l09SG0U
# 5vBwtt0SIDQ98tUO41J/xj36Oyozah2zKsC4n1cdb0p1wEbWdJYSix1vqh+jBT4a
# GlccUeAa/AXcaevZ6JfkWNFNftHyRWZWHzqTmBWvUj3AgyDa5Mh5Z3+m3bQ8+Sgn
# jbjm+u3ZaDHYH0tQAbR1FRqkFCXV8wUd0EGdG4mUEClts01vZBtr68b6g3PklsOo
# 9ppj982vC7BaeFmh2Mmd86GCF5QwgheQBgorBgEEAYI3AwMBMYIXgDCCF3wGCSqG
# SIb3DQEHAqCCF20wghdpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0B
# CRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
# BCBFkvDXJdPY/tdosDjcdKxRg05U+MtENBI7x4/mwCzmhQIGZ1riVeGcGBMyMDI0
# MTIxOTIwMTAwNi40ODRaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046ODYwMy0wNUUwLUQ5
# NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHqMIIH
# IDCCBQigAwIBAgITMwAAAfGzRfUn6MAW1gABAAAB8TANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1NTVaFw0y
# NTAzMDUxODQ1NTVaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYD
# VQQLEx5uU2hpZWxkIFRTUyBFU046ODYwMy0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCxulCZttIf8X97rW9/J+Q4Vg9PiugB1ya1/DRxxLW2hwy4QgtU
# 3j5fV75ZKa6XTTQhW5ClkGl6gp1nd5VBsx4Jb+oU4PsMA2foe8gP9bQNPVxIHMJu
# 6TYcrrn39Hddet2xkdqUhzzySXaPFqFMk2VifEfj+HR6JheNs2LLzm8FDJm+pBdd
# PDLag/R+APIWHyftq9itwM0WP5Z0dfQyI4WlVeUS+votsPbWm+RKsH4FQNhzb0t/
# D4iutcfCK3/LK+xLmS6dmAh7AMKuEUl8i2kdWBDRcc+JWa21SCefx5SPhJEFgYhd
# GPAop3G1l8T33cqrbLtcFJqww4TQiYiCkdysCcnIF0ZqSNAHcfI9SAv3gfkyxqQN
# JJ3sTsg5GPRF95mqgbfQbkFnU17iYbRIPJqwgSLhyB833ZDgmzxbKmJmdDabbzS0
# yGhngHa6+gwVaOUqcHf9w6kwxMo+OqG3QZIcwd5wHECs5rAJZ6PIyFM7Ad2hRUFH
# RTi353I7V4xEgYGuZb6qFx6Pf44i7AjXbptUolDcVzYEdgLQSWiuFajS6Xg3k7Cy
# 8TiM5HPUK9LZInloTxuULSxJmJ7nTjUjOj5xwRmC7x2S/mxql8nvHSCN1OED2/wE
# COot6MEe9bL3nzoKwO8TNlEStq5scd25GA0gMQO+qNXV/xTDOBTJ8zBcGQIDAQAB
# o4IBSTCCAUUwHQYDVR0OBBYEFLy2xe59sCE0SjycqE5Erb4YrS1gMB8GA1UdIwQY
# MBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUt
# U3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB
# /wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0G
# CSqGSIb3DQEBCwUAA4ICAQDhSEjSBFSCbJyl3U/QmFMW2eLPBknnlsfID/7gTMvA
# NEnhq08I9HHbbqiwqDEHSvARvKtL7j0znICYBbMrVSmvgDxU8jAGqMyiLoM80788
# So3+T6IZV//UZRJqBl4oM3bCIQgFGo0VTeQ6RzYL+t1zCUXmmpPmM4xcScVFATXj
# 5Tx7By4ShWUC7Vhm7picDiU5igGjuivRhxPvbpflbh/bsiE5tx5cuOJEJSG+uWcq
# ByR7TC4cGvuavHSjk1iRXT/QjaOEeJoOnfesbOdvJrJdbm+leYLRI67N3cd8B/su
# U21tRdgwOnTk2hOuZKs/kLwaX6NsAbUy9pKsDmTyoWnGmyTWBPiTb2rp5ogo8Y8h
# MU1YQs7rHR5hqilEq88jF+9H8Kccb/1ismJTGnBnRMv68Ud2l5LFhOZ4nRtl4lHr
# i+N1L8EBg7aE8EvPe8Ca9gz8sh2F4COTYd1PHce1ugLvvWW1+aOSpd8NnwEid4zg
# D79ZQxisJqyO4lMWMzAgEeFhUm40FshtzXudAsX5LoCil4rLbHfwYtGOpw9DVX3j
# XAV90tG9iRbcqjtt3vhW9T+L3fAZlMeraWfh7eUmPltMU8lEQOMelo/1ehkIGO7Y
# ZOHxUqeKpmF9QaW8LXTT090AHZ4k6g+tdpZFfCMotyG+E4XqN6ZWtKEBQiE3xL27
# BDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNNMIICNQIB
# ATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UE
# CxMeblNoaWVsZCBUU1MgRVNOOjg2MDMtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNy
# b3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQD7n7Bk4gsM
# 2tbU/i+M3BtRnLj096CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMA0GCSqGSIb3DQEBCwUAAgUA6w6a1zAiGA8yMDI0MTIxOTEzMTUwM1oYDzIw
# MjQxMjIwMTMxNTAzWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDrDprXAgEAMAcC
# AQACAg+kMAcCAQACAhKrMAoCBQDrD+xXAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwG
# CisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEL
# BQADggEBAHawUefJQfDFwseG3XrDfsaiH2d1NSndIbFwwdxP+5iETxeY8NhnCswC
# vTg6GkW4BnyldyYoIf07SJUIxxHq3kn95afODsuTFKC4XZ2eiDRMRuCnXXEdF5mc
# lXW2WNinCmEqWmhAtT7a1mGCOZDWmbWJFeDuO2wQ99U2WxB5mpMm+oO+sWnm5TUx
# v7nWJtVSdfhYP7sT3AOTzRTtGdmNoPypZRFt8OOhos4vA+5t3ez2fB52SD6eawYe
# IJ0fcAX+1XsKAS/O4c4N5TmG5uRq9IhSTZSXLwIUuvkJ4I5j4OX2o/drg9V8Z+Ot
# 5aKsq+UZb6Je+BOdz4Dv8T5ydOLi90kxggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAfGzRfUn6MAW1gABAAAB8TANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCC5KIWFaevNM9KzLnUjX3UPEaPIHpPNUHqMsLlwndpKgDCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EINV3/T5hS7ijwao466RosB7wwEibt0a1P5Eq
# IwEj9hF4MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAHxs0X1J+jAFtYAAQAAAfEwIgQgg3s4cYCh9mlOC+PQPzPakjBC5niQTatwd+Fw
# mS8A9gwwDQYJKoZIhvcNAQELBQAEggIAP+X9yFOPfKnZaNLwvsAPwByybMe3e+Vy
# QlHIJ6JZ2e/lL2jJhwUoPyCvjfbgikO9JCjA3NLxhAlcFw7JHOAVJXOOhQ/kyrr/
# z8BjReVEjTZjS1SHLqQ56ewy6hd/oZUTJIZyGnMcrQo3oELTJqFvku8Z/QEBk4iT
# UrwFcsWW70PksxrNPeOf9hqPAyCq3m5vtoHPI26YIX16iNY3DdG1h5dEW3/FhSTv
# lzK/7SXbqYzX6lKJrA9gVutD3nBE6CGc8wqxNDhvGNNvwhedHq+YmgYppVbYVF7o
# JPn6uUKbh/dewqrAiqlfNkYaTZtChZZYlhLE1YDLY3VHwYgUXCke7hx4jUfAMr4i
# YAQJQaZEA6NtFxkX5jl5f1IR88O/HLERwn6J57QYtJb0vnIFJQg6rvm9X3pG3r05
# EvLWDmKJcEDdlCPsovqi2uTnaMJvIDG+M7ARrErxwayJJEcRKxXn/XzAEVaDkC+5
# lte8/bjFX4VtfM9HyfK6C6WG4AeHcYh50ymxf6/pAHsmdBO0ihkPFMu087o7Jgq2
# g+d3xNFoccAqtNew0haOTJC5zHBgyhdghHFayQh7+i0r/fJjtMYCWDAoIwA+Siya
# LkpoqX9INPXU7lkKYREmKEd9lijmJALcPgWnP6bmG7orjH3MyP0CqUVQTNezAmB3
# 8o6bwQkXuAc=
# SIG # End signature block
