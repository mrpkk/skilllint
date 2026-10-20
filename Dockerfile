FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Схемы акта лежат в .actor/ — Apify читает их при сборке и показывает в Store.
COPY .actor ./.actor

# Порт задаёт платформа (Apify/PaaS) через $PORT или ACTOR_WEB_SERVER_PORT
ENV PORT=8192
ENV HOST=0.0.0.0
ENV MCP_ALLOW_ANY_HOST=1
EXPOSE 8192
CMD ["python3", "apify_run.py"]
