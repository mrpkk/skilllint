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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--http", type=int, default=0)
    ap.add_argument("--http-path", default="/mcp",
                    help="путь MCP внутри HTTP-сервера (туннель не срезает префикс)")
    ap.add_argument("--port", type=int, default=0, help="порт (перекрывает --http); $PORT — для PaaS")
    args = ap.parse_args()
    port = args.port or args.http or int(os.environ.get("PORT", "0") or 0)
    if port:
        # mcp.run() сам поднимает свой event loop (anyio.run) — звать без await и вне asyncio.run
        from mcp.server.transport_security import TransportSecuritySettings
        if os.environ.get("MCP_ALLOW_ANY_HOST") == "1":
            security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
            mcp.run(transport="streamable-http", port=port,
                    streamable_http_path=args.http_path, transport_security=security)
            return
        security = TransportSecuritySettings(
            allowed_hosts=["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*",
                           "rta.lat", "*.rta.lat", "rta.ailegal.legal", "*.ailegal.legal"],
            allowed_origins=["http://127.0.0.1:%d" % port, "http://localhost:%d" % port,
                             "https://rta.lat", "https://*.rta.lat",
                             "https://rta.ailegal.legal", "https://*.ailegal.legal"],
        )
        mcp.run(transport="streamable-http", port=port,
                streamable_http_path=args.http_path, transport_security=security)
    else:
        asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
