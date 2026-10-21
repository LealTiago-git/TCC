# Usando o crAPI como alvo

O [OWASP crAPI](https://github.com/OWASP/crAPI) entra no lab como **segundo alvo
padronizado**, sob o mesmo ciclo de defesa do Juice Shop: todo tráfego passa por
um proxy, é registrado em `access_logs` e recebe `403` quando a IA bloqueia.

O crAPI **não é misturado** no nosso `docker-compose.yml`. Ele roda no compose
oficial dele (projeto Docker separado, rede própria) e o lab só o alcança por um
proxy. Assim os bancos do crAPI não colidem de porta com os do lab.

## Portas

| Porta | Quem | Exposição |
|-------|------|-----------|
| 9001  | `proxy-crapi` (lab) → crAPI | host |
| 8888  | web/API do crAPI | só `127.0.0.1` |
| 5432 / 27017 do crAPI | bancos internos do crAPI | **não exposto** (só na rede do crAPI) |

## Pré-requisito: baixar o crAPI + override

```bash
curl -L -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip /tmp/crapi.zip -d ~/
```

Crie o override ao lado do compose oficial. Ele fecha os bancos do crAPI e expõe
só a API em `127.0.0.1:8888` (precisa de Docker Compose >= 2.24):

```bash
cat > ~/crAPI-main/deploy/docker/docker-compose.crapi-lab.yml <<'EOF'
services:
  crapi-web:
    ports: !override
      - "127.0.0.1:8888:80"
  mailhog:
    ports: !reset []        # reabra "127.0.0.1:8025:8025" se precisar ler e-mails (OTP)
  postgresdb:
    ports: !reset []
  mongodb:
    ports: !reset []
  chromadb:
    ports: !reset []
EOF
```

## Subir

```bash
# 1. crAPI (projeto "crapi", separado)
cd ~/crAPI-main/deploy/docker
docker compose -p crapi -f docker-compose.yml -f docker-compose.crapi-lab.yml --compatibility up -d

# 2. proxy do lab apontando pro crAPI
cd ~/Documents/TCC
docker compose up -d proxy-crapi
```

O serviço `proxy-crapi` (porta 9001) já está no `docker-compose.yml` do lab e
alcança o crAPI via `host.docker.internal:8888`.

## Verificar

```bash
# proxy encaminhando (qualquer código HTTP; 502 = crAPI ainda subindo)
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:9001/identity/health

# entrou no access_logs com alvo "crapi"?
docker exec tcc_proxy_crapi python -c "
import sqlite3
c = sqlite3.connect('access_control.db')
for r in c.execute(\"SELECT id, created_at, ip_address, operation, table_name FROM access_logs WHERE table_name='crapi' ORDER BY id DESC LIMIT 3\"):
    print(r)
"
```

Se aparecer linha com `table_name='crapi'`, o alvo está no ciclo de defesa.

## Notas

- **Ataque o crAPI pela porta 9001** (não 8888) para o tráfego passar pela defesa.
- O `ip_address` registrado é o gateway do Docker (`192.168.65.x`), não o IP real
  da origem — relevante ao interpretar o bloqueio por IP nos experimentos.
- Login de treino: `admin@example.com` / `Admin!123`, ou cadastre um usuário novo
  (senha precisa de 8+ caracteres com maiúscula, número e símbolo).
- Parar o crAPI: `docker compose -p crapi down` (adicione `--volumes` para zerar os dados).
