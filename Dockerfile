FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PORT=8192
ENV MCP_ALLOW_ANY_HOST=1
EXPOSE 8192
# streamable-http MCP; путь задаётся переменной MCP_PATH
CMD ["python3", "mcp_server.py", "--port", "8192", "--http-path", "/mcp"]
