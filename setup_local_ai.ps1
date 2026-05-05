# Setup para Ollama local
Write-Host "=== Configurando AI Local ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Verificando Ollama..." -ForegroundColor Yellow
$ollama = Get-Process ollama -ErrorAction SilentlyContinue
if ($ollama) {
    Write-Host "Ollama esta rodando." -ForegroundColor Green
} else {
    Write-Host "Ollama NAO esta rodando." -ForegroundColor Red
    Write-Host "Por favor, abra o app Ollama primeiro." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "Configurando variaveis de ambiente..." -ForegroundColor Yellow
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"
Write-Host "Variaveis configuradas!" -ForegroundColor Green

Write-Host ""
Write-Host "Testando conexao com Ollama..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -ErrorAction Stop
    Write-Host "Conectado com sucesso!" -ForegroundColor Green
    $models = $response.models | ForEach-Object { $_.name }
    Write-Host "Modelos disponíveis: $($models -join ', ')" -ForegroundColor Green
} catch {
    Write-Host "Erro ao conectar: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "PRONTO!" -ForegroundColor Green
Write-Host ""
Write-Host "Agora execute:" -ForegroundColor Cyan
Write-Host "python -m access_defense.cli simulate --ai gemma3" -ForegroundColor White
Write-Host "   ou" -ForegroundColor Gray
Write-Host "python -m access_defense.cli simulate --ai qwen2.5" -ForegroundColor White
Write-Host "   ou" -ForegroundColor Gray
Write-Host "python -m access_defense.cli simulate --ai both" -ForegroundColor White
