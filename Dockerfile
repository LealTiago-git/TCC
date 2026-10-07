# Imagem unica p/ todos os papeis Python do lab (server, proxy, agent, dashboard).
# Papel escolhido via `command` no docker-compose.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir -U pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Default = servidor vulneravel. Compose sobrescreve p/ proxy/agent/dashboard.
CMD ["python", "-m", "access_defense.server", "--host", "0.0.0.0", "--port", "8000"]
