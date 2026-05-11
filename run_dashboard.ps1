# Script: run_dashboard.ps1
# Propósito: Iniciar a dashboard Streamlit com configurações automáticas
# Uso: powershell -ExecutionPolicy Bypass -File run_dashboard.ps1

param(
    [string]$Port = "8501",
    [switch]$NoOpen = $false
)

Write-Host "=== Iniciando Dashboard Streamlit ===" -ForegroundColor Cyan
Write-Host ""

# Verificar se o banco existe
$dbPath = "access_control.db"
if (-not (Test-Path $dbPath)) {
    Write-Host "⚠️  Banco de dados não encontrado!" -ForegroundColor Yellow
    Write-Host "Inicializando banco..." -ForegroundColor Yellow
    python -m access_defense.cli init-db
    Write-Host ""
}

# Iniciar dashboard
Write-Host "🚀 Iniciando dashboard na porta $Port..." -ForegroundColor Green
Write-Host "📊 Acesse: http://localhost:$Port" -ForegroundColor Green
Write-Host "💡 Pressione CTRL+C para parar" -ForegroundColor Yellow
Write-Host ""

streamlit run access_defense/dashboard.py --server.port=$Port
