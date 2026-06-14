$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Host "Виртуальное окружение не найдено. Создаю .venv..."
    python -m venv (Join-Path $ProjectRoot ".venv")
}

Write-Host "Устанавливаю зависимости проекта..."
& $Python -m pip install -r (Join-Path $ProjectRoot "traffic_analyzer\requirements.txt")

Write-Host "Устанавливаю PyInstaller для сборки EXE..."
& $Python -m pip install pyinstaller

Write-Host "Собираю DRAKKAR_NetScanner.exe..."
& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name DRAKKAR_NetScanner `
    --collect-all scapy `
    --collect-all pyqtgraph `
    --hidden-import scapy.layers.http `
    --hidden-import scapy.arch.windows `
    (Join-Path $ProjectRoot "traffic_analyzer\main.py")

Write-Host ""
Write-Host "Готово. EXE-файл находится здесь:"
Write-Host (Join-Path $ProjectRoot "dist\DRAKKAR_NetScanner.exe")
Write-Host ""
Write-Host "Важно: для захвата пакетов на Windows все равно нужен Npcap:"
Write-Host "https://npcap.com/#download"
