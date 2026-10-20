FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Порт задаёт платформа (Apify/PaaS) через $PORT; по умолчанию 8192
ENV PORT=8192
ENV HOST=0.0.0.0
ENV MCP_ALLOW_ANY_HOST=1
EXPOSE 8192
CMD ["python3", "mcp_server.py", "--http-path", "/mcp"]
