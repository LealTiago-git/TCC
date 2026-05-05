# Rodando com IAs Locais (Ollama)

## Status Atual

✓ Ollama está rodando
✓ Gemma 3 está instalado
✓ Qwen 2.5 está instalado
✓ Código funciona perfeitamente

## Como Usar

### 1. Terminal Principal - Deixe o Ollama rodando

O Ollama deve estar sempre rodando em background. Se não estiver:
- Abra: `C:\Users\{seu_usuario}\AppData\Local\Programs\Ollama\ollama.exe`
- Deixe a janela aberta

### 2. Configurar Variáveis de Ambiente

Execute ISSO EM CADA NOVO TERMINAL POWERSHELL antes de rodar os comandos:

```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"
```

### 3. Executar com IA

Com essas variáveis configuradas, execute qualquer um:

```powershell
# Testar com Gemma 3
python -m access_defense.cli simulate --ai gemma3

# Testar com Qwen 2.5
python -m access_defense.cli simulate --ai qwen2.5

# Testar com as duas (sequencial)
python -m access_defense.cli simulate --ai both

# Deixar em alerta monitorando
python -m access_defense.cli monitor --ai gemma3

# Gerar um ataque controlado
python -m access_defense.cli attack --mode ddos
```

## Se Algo Não Funcionar

### Problema: Conexão recusada / Timeout

**Solução:**
1. Verifique se Ollama está rodando: veja se a janela está aberta
2. Reinicie o Ollama se necessário
3. Espere alguns segundos após iniciar antes de rodar o código

### Problema: Modelo não disponível

**Solução:**
```powershell
# Se Gemma 3 não aparecer:
ollama pull gemma3

# Se Qwen 2.5 não aparecer:
ollama pull qwen2.5
```

### Problema: Banco de dados travado

**Solução:**
```powershell
# Remova o banco
Remove-Item "access_control.db" -Force

# Reinitialize
python -m access_defense.cli init-db
```

## Verificar o Que Está Funcionando

```powershell
# Ver os logs de acesso
python -m access_defense.cli show-logs

# Ver os alertas gerados
python -m access_defense.cli show-alerts

# Ver histórico de respostas da IA
python -m access_defense.cli show-responses

# Ver resultados e performance das IAs
python -m access_defense.cli show-ai-results
```

## Workflow Recomendado

**Terminal 1** - Deixe rodando:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"
python -m access_defense.cli monitor --ai gemma3
```

**Terminal 2** - Gere ataques:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"
python -m access_defense.cli attack --mode ddos
python -m access_defense.cli attack --mode injection
python -m access_defense.cli attack --mode brute-force
```

O Terminal 1 detectará os ataques em tempo real!

## Script Automático (Opcional)

Se quiser facilitar, use o script que criamos:

```powershell
powershell -ExecutionPolicy Bypass -File "c:\Users\tiago\Documents\TCC\setup_local_ai.ps1"
```

Ele verifica Ollama e configura automaticamente as variáveis.

## Modelos Alternativo

Você também pode usar outros modelos do Ollama:

```powershell
# Listar modelos disponíveis
ollama list

# Usar outro modelo (ex: mistral)
$env:QWEN_MODEL="mistral"
python -m access_defense.cli simulate --ai qwen2.5
```

---

**Pronto!** Agora você pode rodar tudo com IAs locais sem precisar do OpenRouter.
