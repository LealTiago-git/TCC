# Orquestrador end-to-end do TCC.
# Sobe Docker (Postgres+Mongo), server vulneravel, agente IA, dashboard.
# Depois roda atacante e mede metricas.
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1 -Model qwen2.5 -SkipDocker

param(
    [string]$Model = "qwen2.5",
    [int]$ServerPort = 8000,
    [int]$DashboardPort = 8501,
    [int]$AgentInterval = 3,
    [string]$AttackMode = "full",
    [switch]$SkipDocker = $false,
    [switch]$SkipDashboard = $false
)

$ErrorActionPreference = "Continue"
$LogDir = "logs"
New-Item -ItemType Directory -Force $LogDir | Out-Null

function Write-Step {
    param([string]$Msg)
    Write-Host ""
    Write-Host "=== $Msg ===" -ForegroundColor Cyan
}

function Stop-AllJobs {
    Write-Step "Parando processos de background"
    Get-Job | Stop-Job -ErrorAction SilentlyContinue
    Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
}

function Ensure-DockerOnPath {
    if (Get-Command docker -ErrorAction SilentlyContinue) { return $true }
    $dockerBin = "C:\Program Files\Docker\Docker\resources\bin"
    if (Test-Path "$dockerBin\docker.exe") {
        $env:PATH = "$dockerBin;$env:PATH"
        Write-Host "[docker] PATH ajustado para incluir $dockerBin" -ForegroundColor Yellow
        return $true
    }
    Write-Host "[docker] docker.exe nao encontrado. Instale Docker Desktop." -ForegroundColor Red
    return $false
}

function Test-DockerDaemon {
    docker info 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Start-DockerDesktop {
    $candidates = @(
        "C:\Program Files\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) {
            Write-Host "[docker] Iniciando Docker Desktop: $p" -ForegroundColor Yellow
            Start-Process -FilePath $p
            return $true
        }
    }
    Write-Host "[docker] Docker Desktop.exe nao encontrado." -ForegroundColor Red
    return $false
}

function Wait-DockerDaemon {
    param([int]$TimeoutSeconds = 120)
    Write-Host "[docker] Aguardando daemon ficar pronto (max ${TimeoutSeconds}s)..." -ForegroundColor Yellow
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-DockerDaemon) {
            Write-Host "[docker] Daemon pronto!" -ForegroundColor Green
            return $true
        }
        Start-Sleep -Seconds 3
        Write-Host "  ainda aguardando..." -ForegroundColor Gray
    }
    return $false
}

# 1. Docker
if (-not $SkipDocker) {
    Write-Step "Verificando Docker"
    if (-not (Ensure-DockerOnPath)) {
        Write-Host "Use -SkipDocker se Docker nao esta disponivel." -ForegroundColor Red
        exit 1
    }
    if (-not (Test-DockerDaemon)) {
        Write-Host "[docker] Daemon nao esta rodando. Tentando iniciar Docker Desktop..." -ForegroundColor Yellow
        if (-not (Start-DockerDesktop)) {
            exit 1
        }
        if (-not (Wait-DockerDaemon -TimeoutSeconds 120)) {
            Write-Host "[docker] Daemon nao subiu em 120s. Abra Docker Desktop manualmente e tente de novo." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[docker] Daemon ja esta rodando." -ForegroundColor Green
    }

    Write-Step "Subindo Postgres + Mongo via docker compose"
    docker compose up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker compose falhou. Veja erro acima." -ForegroundColor Red
        exit 1
    }
    Write-Host "Aguardando 8s para containers estabilizarem..."
    Start-Sleep -Seconds 8
}

# 2. Variaveis de ambiente do Ollama
Write-Step "Configurando Ollama"
$env:AGENT_PROVIDER = "ollama"
$env:OLLAMA_NATIVE_URL = "http://localhost:11434"
$env:OLLAMA_API_KEY = "ollama"

# 3. Init DB (SQLite local pra logs)
Write-Step "Inicializando schema SQLite"
python -m access_defense.cli init-db

# 4. Server vulneravel em background
Write-Step "Iniciando servidor vulneravel na porta $ServerPort"
$serverJob = Start-Job -Name "server" -ScriptBlock {
    param($Port)
    python -m access_defense.server --port $Port 2>&1
} -ArgumentList $ServerPort
Start-Sleep -Seconds 4

# 5. Health check do server
$health = Invoke-RestMethod -Uri "http://localhost:$ServerPort/health" -ErrorAction SilentlyContinue
if ($null -eq $health) {
    Write-Host "Server nao subiu. Veja logs/server.log" -ForegroundColor Red
    Stop-AllJobs
    exit 1
}
Write-Host "Health: $($health | ConvertTo-Json -Compress)" -ForegroundColor Green

# 6. Agente IA em background
Write-Step "Iniciando agente IA ($Model)"
$agentJob = Start-Job -Name "agent" -ScriptBlock {
    param($Mod, $Int)
    $env:AGENT_PROVIDER = "ollama"
    $env:OLLAMA_NATIVE_URL = "http://localhost:11434"
    $env:OLLAMA_API_KEY = "ollama"
    python -m access_defense.agent_loop --model $Mod --interval $Int 2>&1
} -ArgumentList $Model, $AgentInterval
Start-Sleep -Seconds 2

# 7. Dashboard (opcional)
if (-not $SkipDashboard) {
    Write-Step "Iniciando dashboard Streamlit na porta $DashboardPort"
    $dashJob = Start-Job -Name "dashboard" -ScriptBlock {
        param($Port)
        python -m streamlit run access_defense/dashboard.py --server.headless true --server.port $Port 2>&1
    } -ArgumentList $DashboardPort
    Start-Sleep -Seconds 4
    Write-Host "Dashboard: http://localhost:$DashboardPort" -ForegroundColor Green
}

# 8. Atacante
Write-Step "Disparando atacante (modo=$AttackMode)"
$attackReport = python -m access_defense.attacker --target "http://localhost:$ServerPort" --mode $AttackMode 2>&1
Write-Host $attackReport

# 9. Aguardar agente processar
Write-Step "Aguardando agente IA processar (15s)"
Start-Sleep -Seconds 15

# 10. Metricas
Write-Step "Metricas de defesa"
python -m access_defense.metrics

Write-Host ""
Write-Host "Demo em execucao. Background jobs:" -ForegroundColor Yellow
Get-Job | Format-Table Name, State, HasMoreData

Write-Host ""
Write-Host "Para parar tudo:" -ForegroundColor Yellow
Write-Host "  Get-Job | Stop-Job; Get-Job | Remove-Job"
Write-Host "  docker compose down"
