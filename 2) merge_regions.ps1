# merge_regions.ps1
# Объединяет все файлы region_*.bin в один full_mem.bin, сортируя по hex-адресу

# Перейти в папку с дампом
Set-Location "...\mem_dump"

# Путь к выходному файлу
$out = Join-Path (Get-Location) "full_mem.bin"

# Удаляем старый full_mem.bin если он существует
if (Test-Path $out) {
    Remove-Item $out -Force
}

# Получаем список файлов и сортируем по числовому значению hex из имени
$parts = Get-ChildItem -Filter "region_*.bin" | ForEach-Object {
    $hex = $_.Name -replace '^region_','' -replace '\.bin$',''
    [PSCustomObject]@{
        File = $_.FullName
        Hex = $hex
        Num = [convert]::ToInt64($hex,16)
    }
} | Sort-Object Num

# Если нет файлов, выходим
if ($parts.Count -eq 0) {
    Write-Host "No region_*.bin files found in the folder." -ForegroundColor Yellow
    exit 1
}

# Создаём выходной файл
$fsOut = [System.IO.File]::Open($out,
    [System.IO.FileMode]::Create,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
)

try {
    foreach ($p in $parts) {
        Write-Host ("Appending " + (Split-Path $p.File -Leaf) + " (base 0x" + $p.Hex + ")")
        $fsIn = [System.IO.File]::Open(
            $p.File,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
            $buffer = New-Object byte[] 65536
            while (($read = $fsIn.Read($buffer,0,$buffer.Length)) -gt 0) {
                $fsOut.Write($buffer,0,$read)
            }
        } finally {
            $fsIn.Close()
        }
    }
} finally {
    $fsOut.Close()
}

Write-Host ("Merged -> " + $out) -ForegroundColor Green

