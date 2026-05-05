# Script: run_with_local_ai.ps1
# Uso: powershell -ExecutionPolicy Bypass -File run_with_local_ai.ps1 gemma3 simulate

param(
    [string]$Model = "gemma3",
    [string]$Command = "simulate",
    [string]$Mode = "off"
)

# Configurar ambiente
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"

Write-Host "Configurado para rodar com: $Model" -ForegroundColor Cyan
Write-Host ""

# Verificar Ollama
$ollama = Get-Process ollama -ErrorAction SilentlyContinue
if (-not $ollama) {
    Write-Host "ERRO: Ollama nao esta rodando!" -ForegroundColor Red
    Write-Host "Abra: C:\Users\$env:USERNAME\AppData\Local\Programs\Ollama\ollama.exe" -ForegroundColor Yellow
    exit 1
}

# Executar comando
$fullCommand = "python -m access_defense.cli $Command --ai $Model"
if ($Mode -ne "off") {
    $fullCommand = "python -m access_defense.cli $Command --mode $Mode"
}

Write-Host "Executando: $fullCommand" -ForegroundColor Green
Write-Host ""

Invoke-Expression $fullCommand
