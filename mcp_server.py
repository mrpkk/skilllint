#!/usr/bin/env python3
"""MCP-сервер skilllint — проверка качества и безопасности скиллов агента.

Приватный по построению: проверка локальная, наружу не уходит ничего.
Даёт: вердикт + воспроизводимый хеш (основа для подписи attest).

Запуск:  python3 mcp_server.py            # stdio
         python3 mcp_server.py --http 8191
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skilllint.linter import compare, lint_skill, rules  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402

mcp = MCPServer("skilllint", version="1.0.0")


@mcp.tool(name="lint_skill", description="Проверить SKILL.md: структура, триггеры, секреты, инъекции, битые ссылки, автономия. Возвращает вердикт, балл и sha256.")
async def lint_skill_tool(path: str) -> str:
    return json.dumps(lint_skill(path).as_dict(), ensure_ascii=False)


@mcp.tool(name="compare_skills", description="Сравнить нескольких кандидатов из разных реестров и ранжировать по вердикту и доказательной базе.")
async def compare_skills_tool(paths: str) -> str:
    items = [p.strip() for p in paths.replace("\n", ",").split(",") if p.strip()]
    if not items:
        return json.dumps({"error": "перечисли пути через запятую"}, ensure_ascii=False)
    return json.dumps({"candidates": compare(items)}, ensure_ascii=False)


@mcp.tool(name="lint_rules", description="Список правил линтера с идентификаторами и severity.")
async def lint_rules_tool() -> str:
    return json.dumps({"rules": rules()}, ensure_ascii=False)


_PRIVACY = '# Privacy — skilllint\n\nskilllint answers one question about one input. Here is the whole data story.\n\n## What is stored\n\n- **Request counters** — how many calls, of which tool, per day. No content.\n- **The rate limiter** keeps your client address in memory for one hour to count\n  requests. It is not written to disk and disappears on restart.\n- **Errors** are logged without request bodies.\n\n## What is not stored\n\n- the artifact, the skill text, the prompt, the file name, the model output;\n- anything that identifies you personally;\n- IP addresses in persistent form.\n\n## Paid calls\n\nA payment receipt is a public on-chain fact. It carries the amount, the payer\naddress and the time — nothing about the content you verified.\n\n## Deletion and questions\n\nOpen an issue at https://github.com/mrpkk/skilllint/issues. There is no account to delete: the service does\nnot have users, only callers.\n'

_LLMS_INSTALL = '# skilllint — install\n\nRemote MCP server (streamable HTTP). No key, no account.\n\n```json\n{"mcpServers": {"skilllint": {"url": "https://rta.lat/skilllint/mcp"}}}\n```\n\nTools: `lint_skill` — проверить SKILL.md (структура, триггеры, секреты, инъекции, битые ссылки, автономия), `compare_skills` — сравнить кандидатов, `lint_rules` — список правил.\n\nFree, без регистрации.\n\nEndpoint: `https://rta.lat/skilllint/mcp` · Health: `https://rta.lat/skilllint/health` · Privacy: `https://rta.lat/skilllint/privacy` · Source: https://github.com/mrpkk/skilllint\n'

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--http", type=int, default=0)
    ap.add_argument("--http-path", default="/mcp",
                    help="путь MCP внутри HTTP-сервера (туннель не срезает префикс)")
    ap.add_argument("--port", type=int, default=0, help="порт (перекрывает --http); $PORT — для PaaS")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"), help="bind-адрес (0.0.0.0 в контейнерах)")
    args = ap.parse_args()
    port = args.port or args.http or int(os.environ.get("PORT", "0") or 0)
    if port:
        # HTTP-режим через ASGI-приложение: так добавляется /health —
        # Apify и внешние платформы проверяют стартовый URL, прежде чем считать акт живым.
        from mcp.server.transport_security import TransportSecuritySettings
        if os.environ.get("MCP_ALLOW_ANY_HOST") == "1":
            security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        else:
            security = TransportSecuritySettings(
                allowed_hosts=["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*",
                               "rta.lat", "*.rta.lat", "rta.ailegal.legal", "*.ailegal.legal"],
                allowed_origins=["http://127.0.0.1:%d % port", "http://localhost:%d % port",
                                 "https://rta.lat", "https://*.rta.lat",
                                 "https://rta.ailegal.legal", "https://*.ailegal.legal"],
            )
        import uvicorn
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        app = mcp.streamable_http_app(streamable_http_path=args.http_path,
                                       transport_security=security)

        async def _health(request):
            return JSONResponse({"ok": True, "service": "skilllint",
                                 "mcp_path": args.http_path})

        from starlette.responses import PlainTextResponse

        async def _privacy(request):
            return PlainTextResponse(_PRIVACY, media_type="text/plain; charset=utf-8")

        async def _llms(request):
            return PlainTextResponse(_LLMS_INSTALL, media_type="text/plain; charset=utf-8")

        _prefix = args.http_path.rsplit("/", 1)[0]
        for _p in ("/privacy", _prefix + "/privacy"):
            app.router.routes.insert(0, Route(_p, _privacy))
        for _p in ("/llms-install.md", _prefix + "/llms-install.md"):
            app.router.routes.insert(0, Route(_p, _llms))
        async def _server_card(request):
            # Статическая карточка для каталогов, где скан живого /mcp не
            # проходит. Собирается из того же списка инструментов, что и
            # tools/list, — расхождение с листингом невозможно.
            tools = await mcp.list_tools()
            card = {
                "serverInfo": {"name": "skilllint", "version": "1.0.0"},
                "authentication": {"required": False, "schemes": []},
                "tools": [{"name": x.name, "description": x.description or "",
                           # В новом SDK поле называется input_schema,
                           # в старом — inputSchema.
                           "inputSchema": getattr(x, "inputSchema", None)
                           or getattr(x, "input_schema", None)
                           or {"type": "object"}}
                          for x in tools],
                "resources": [],
                "prompts": [],
            }
            return JSONResponse(card)

        _prefix = args.http_path.rsplit("/", 1)[0]
        for _p in ("/.well-known/mcp/server-card.json", _prefix + "/.well-known/mcp/server-card.json"):
            app.router.routes.insert(0, Route(_p, _server_card))
        app.router.routes.insert(0, Route("/health", _health))
        app.router.routes.insert(0, Route("/", _health))
        # тот же health под префиксом туннеля (/mitracore/health, /skilllint/health)
        prefix = args.http_path.rsplit("/", 1)[0]
        if prefix and prefix != "":
            app.router.routes.insert(0, Route(prefix + "/health", _health))
        uvicorn.run(app, host=args.host, port=port, log_level="warning")
    else:
        asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
