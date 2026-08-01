$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$vendorRoot = Join-Path $repositoryRoot "vendor/p04"
$expected = [ordered]@{
    "Deep.Protocol.0.3.0-p04.b887fa0.nupkg" = "8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442"
    "Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg" = "fc1212a6765f5778188fcb3866ef923023c2253c3ead299a542271f4cc4f844f"
    "Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg" = "755a027c58be670151456cc0bca4764731f7c493932d9eedd00c02e704baf818"
    "package-manifest.json" = "fd3ef27bf0b9272570d6c6e680a3c99e581f6220799d13ee3afbd86ea0e99298"
    "membership-contract-v1.json" = "758707e4705c0499f546ce1e1e5201df253ef70822225c5fd3086c43d8d9bf45"
}

function Get-CanonicalTextSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

$actualFiles = @(
    Get-ChildItem -LiteralPath $vendorRoot -File |
        Sort-Object -Property Name |
        Select-Object -ExpandProperty Name
)
$expectedFiles = @($expected.Keys | Sort-Object)
if (Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $actualFiles) {
    throw "P04 vendor inventory differs from the accepted five-file set."
}

foreach ($entry in $expected.GetEnumerator()) {
    $path = Join-Path $vendorRoot $entry.Key
    $actual = if ($entry.Key.EndsWith(".json", [StringComparison]::Ordinal)) {
        Get-CanonicalTextSha256 -Path $path
    }
    else {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    }
    if ($actual -ne $entry.Value) {
        throw "P04 pin mismatch for $($entry.Key)."
    }
}

Write-Output "P04 vendor hash gate passed (5/5 exact files)."
