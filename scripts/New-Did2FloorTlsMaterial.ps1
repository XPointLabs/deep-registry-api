param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $ServerDnsName,

    [string] $OpenSslPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory)) {
    throw 'The floor TLS output directory must be absolute.'
}
if ($ServerDnsName -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$') {
    throw 'The floor server name must be one exact DNS hostname.'
}
$target = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $target) {
    throw 'The floor TLS output directory already exists; refusing to overwrite keys.'
}
$parent = [IO.Path]::GetDirectoryName($target)
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Create a private parent directory before authoring floor TLS secrets.'
}
$permitted = @(
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
    'S-1-5-18', 'S-1-5-32-544')
foreach ($rule in (Get-Acl -LiteralPath $parent).Access) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value -notin $permitted) {
        throw 'The floor TLS parent grants access beyond owner, SYSTEM and Administrators.'
    }
}
if ([string]::IsNullOrWhiteSpace($OpenSslPath)) {
    $found = Get-Command openssl -ErrorAction SilentlyContinue
    if ($null -ne $found) {
        $OpenSslPath = $found.Source
    } elseif (Test-Path -LiteralPath 'C:\Program Files\Git\usr\bin\openssl.exe') {
        $OpenSslPath = 'C:\Program Files\Git\usr\bin\openssl.exe'
    } else {
        throw 'OpenSSL 3 is required to author the private floor TLS certificates.'
    }
}
if (-not (Test-Path -LiteralPath $OpenSslPath -PathType Leaf)) {
    throw 'The selected OpenSSL executable is absent.'
}

function Invoke-OpenSsl([string[]] $Arguments) {
    & $OpenSslPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL floor TLS authoring failed (exit $LASTEXITCODE)."
    }
}

New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
$acl = Get-Acl -LiteralPath $target
$acl.SetAccessRuleProtection($true, $false)
$inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach ($sid in $permitted) {
    $identity = [Security.Principal.SecurityIdentifier]::new($sid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $identity, [Security.AccessControl.FileSystemRights]::FullControl,
        $inherit, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $target -AclObject $acl
$caKey = Join-Path $target 'floor-ca.key.pem'
$caCertificate = Join-Path $target 'floor-ca.crt.pem'
$serverKey = Join-Path $target 'floor-server.key.pem'
$serverRequest = Join-Path $target 'floor-server.csr.pem'
$serverCertificate = Join-Path $target 'floor-server.crt.pem'

Invoke-OpenSsl @('genpkey', '-algorithm', 'ED25519', '-out', $caKey)
Invoke-OpenSsl @(
    'req', '-new', '-x509', '-key', $caKey, '-days', '1825',
    '-subj', '/CN=Deep-DID2-Floor-Internal-CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-out', $caCertificate)
Invoke-OpenSsl @(
    'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
    '-out', $serverKey)
Invoke-OpenSsl @(
    'req', '-new', '-key', $serverKey, '-subj', "/CN=$ServerDnsName",
    '-addext', "subjectAltName=DNS:$ServerDnsName",
    '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
    '-addext', 'extendedKeyUsage=serverAuth',
    '-out', $serverRequest)
Invoke-OpenSsl @(
    'x509', '-req', '-in', $serverRequest,
    '-CA', $caCertificate, '-CAkey', $caKey, '-CAcreateserial',
    '-days', '397', '-copy_extensions', 'copy',
    '-out', $serverCertificate)
Invoke-OpenSsl @(
    'verify', '-CAfile', $caCertificate, '-verify_hostname', $ServerDnsName,
    '-purpose', 'sslserver', $serverCertificate)

foreach ($name in @('postgres-admin.password', 'floor-provision.password',
        'floor-runtime.password')) {
    $password = [Convert]::ToHexStringLower(
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    try {
        [IO.File]::WriteAllText((Join-Path $target $name), $password,
            [Text.UTF8Encoding]::new($false))
    } finally {
        $password = $null
    }
}

foreach ($file in Get-ChildItem -LiteralPath $target -File) {
    $fileAcl = Get-Acl -LiteralPath $file.FullName
    foreach ($rule in $fileAcl.Access) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value -notin $permitted) {
            throw 'Generated floor TLS material inherited an unsafe access rule.'
        }
    }
}

Write-Output "DID2 floor TLS material authored and verified for $ServerDnsName."
Write-Output 'Keep floor-ca.key.pem offline. Copy only the CA certificate, server certificate, server key and role credentials required by the floor host.'
Invoke-OpenSsl @('x509', '-in', $serverCertificate, '-noout', '-fingerprint', '-sha256')
