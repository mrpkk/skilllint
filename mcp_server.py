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
from mcp.types import ToolAnnotations  # noqa: E402
import x402_gate  # noqa: E402  (цена и 402 после бесплатного лимита)

mcp = MCPServer("skilllint", version="1.0.0")

# Описания и аннотации — на английском и с readOnlyHint: каталоги (Glama,
# mcpservers.org, реестр MCP) показывают аннотации бейджем «read-only» и
# отсеивают серверы без них. Русский текст там читают только те, кто ищет
# русскоязычный листинг.
_READONLY = dict(read_only_hint=True, destructive_hint=False,
                 idempotent_hint=True, open_world_hint=False)


@mcp.tool(
    name="lint_skill",
    title="Vet an agent skill",
    description=("Vet a SKILL.md before you install it: structure, trigger quality, "
                 "leaked secrets, prompt-injection markers, broken links and autonomy "
                 "claims. Returns a verdict, a score and a sha256 of the checked file."),
    annotations=ToolAnnotations(title="Vet an agent skill", **_READONLY),
)
async def lint_skill_tool(path: str) -> str:
    return json.dumps(lint_skill(path).as_dict(), ensure_ascii=False)


@mcp.tool(
    name="compare_skills",
    title="Compare agent skills",
    description=("Compare candidate skills from different registries and rank them by "
                 "verdict and evidence quality. Takes a comma-separated list of paths."),
    annotations=ToolAnnotations(title="Compare agent skills", **_READONLY),
)
async def compare_skills_tool(paths: str) -> str:
    items = [p.strip() for p in paths.replace("\n", ",").split(",") if p.strip()]
    if not items:
        return json.dumps({"error": "перечисли пути через запятую"}, ensure_ascii=False)
    return json.dumps({"candidates": compare(items)}, ensure_ascii=False)


@mcp.tool(
    name="lint_rules",
    title="List lint rules",
    description=("List the linter's rules with their identifiers and severity levels."),
    annotations=ToolAnnotations(title="List lint rules", **_READONLY),
)
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
                "tools": [{"name": x.name,
                           "title": getattr(x, "title", None) or x.name,
                           "description": x.description or "",
                           # Аннотации — те же, что отдаёт tools/list:
                           # каталоги читают статическую карточку, когда
                           # живой скан не проходит.
                           "annotations": (x.annotations.model_dump(by_alias=True, exclude_none=True)
                                           if getattr(x, "annotations", None) else None),
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

        # ── цена и оплата ───────────────────────────────────────────────
        # Бесплатный лимит в день, дальше 402 по x402. Адрес страницы цены
        # уходит в server.json (websiteUrl): без него каталоги не показывают
        # цену вовсе — они читают её с сайта, а не из нашего ответа.
        gate_cfg = x402_gate.config("skilllint",
                                    f"https://rta.lat{args.http_path}")
        if gate_cfg is not None:
            from starlette.requests import Request

            async def _pricing(request):
                return JSONResponse(
                    {"service": "skilllint", "price_usd": gate_cfg.price_usd,
                     "free_per_day": gate_cfg.free_per_day,
                     "subscription_usd": gate_cfg.sub_price_usd,
                     "subscription_period_days": 30,
                     "network": gate_cfg.network, "pay_to": gate_cfg.pay_to,
                     "resource": gate_cfg.resource},
                    headers={"Cache-Control": "no-store"})

            async def _pricing_html(request):
                from starlette.responses import HTMLResponse
                page = x402_gate.pricing_page(
                    gate_cfg, title="skilllint — vet an agent skill before install",
                    what=("Structure, triggers, secrets, prompt-injection, broken links "
                          "and autonomy — one verdict with a reproducible hash."),
                    docs="https://rta.lat/skilllint/llms-install.md")
                return HTMLResponse(page, headers={"Cache-Control": "no-store"})

            async def _subscribe(request: Request):
                status, body, extra = x402_gate.subscribe(
                    gate_cfg, request.headers.get("x-payment")
                    or request.headers.get("payment-signature") or "")
                return JSONResponse(body, status_code=status, headers=extra)

            app.router.routes.insert(0, Route("/pricing.json", _pricing))
            app.router.routes.insert(0, Route(_prefix + "/pricing.json", _pricing))
            app.router.routes.insert(0, Route("/pricing", _pricing_html))
            app.router.routes.insert(0, Route(_prefix + "/pricing", _pricing_html))
            app.router.routes.insert(0, Route("/subscribe", _subscribe,
                                              methods=["POST"]))
            app.router.routes.insert(0, Route(_prefix + "/subscribe", _subscribe,
                                              methods=["POST"]))

        app.router.routes.insert(0, Route("/health", _health))
        app.router.routes.insert(0, Route("/", _health))
        # тот же health под префиксом туннеля (/mitracore/health, /skilllint/health)
        prefix = args.http_path.rsplit("/", 1)[0]
        if prefix and prefix != "":
            # Голый префикс тоже отвечает: человек, открывший https://rta.lat/skilllint,
            # должен увидеть карточку сервера, а не 404.
            app.router.routes.insert(0, Route(prefix, _health))
            app.router.routes.insert(0, Route(prefix + "/health", _health))
        # Гейт ставится последним: он оборачивает уже собранное приложение,
        # и 402 решается до парсера MCP, а не внутри инструмента.
        if gate_cfg is not None:
            app = x402_gate.middleware(
                gate_cfg, x402_gate.DailyQuota(gate_cfg.free_per_day))(app)
        uvicorn.run(app, host=args.host, port=port, log_level="warning")
    else:
        asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
