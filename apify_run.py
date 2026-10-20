#!/usr/bin/env python3
"""Режим запуска Apify для skilllint: SKILL.md → вердикт в dataset.

Действие акта: принять текст скилла (или ссылку на него) и вернуть
вердикт линтера — балл, sha256 и находки. Всё считается локально:
ничего не уходит из контейнера.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

API = "https://api.apify.com/v2"
UA = "apify-actor/1.0"


def _api(method: str, url: str, payload=None, timeout: int = 30):
    """Запрос к Apify API. Токен платформа внедряет в контейнер (APIFY_TOKEN)."""
    data = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": UA,
                                          "Authorization": f"Bearer {os.environ.get('APIFY_TOKEN', '')}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:400].decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def read_input() -> dict:
    """Вход прогона: из ACTOR_INPUT, иначе из KV-хранилища по ACTOR_INPUT_KEY."""
    raw = os.environ.get("ACTOR_INPUT")
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            return {}
    token = os.environ.get("APIFY_TOKEN")
    key = os.environ.get("ACTOR_INPUT_KEY")
    store = os.environ.get("ACTOR_DEFAULT_KEY_VALUE_STORE_ID")
    if not (token and key and store):
        print(f"apify_run: нет переменных прогона (token={bool(token)}, key={bool(key)}, store={bool(store)})",
              flush=True)
        return {}
    status, body = _api("GET", f"{API}/key-value-stores/{store}/records/{key}")
    print(f"apify_run: чтение входа key={key} store={store} -> HTTP {status}", flush=True)
    if status != 200 or not isinstance(body, dict):
        print(f"apify_run: ответ: {str(body)[:200]}", flush=True)
        return {}
    # Ответ Apify обёрнут в {"data": {...}} — значение записи лежит в data.value
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    value = data.get("value")
    if not isinstance(value, dict):
        return {}
    # Apify кладёт вход в запись как {"input": {...}, "filename": ...} —
    # разворачиваем обёртку, иначе действие увидит пустой вход.
    inner = value.get("input")
    if isinstance(inner, dict) and inner:
        return inner
    return value


def write_output(item: dict) -> None:
    """Результат — в dataset прогона и в KV-запись OUTPUT."""
    if os.environ.get("APIFY_TOKEN") and os.environ.get("ACTOR_DEFAULT_DATASET_ID"):
        status, body = _api("POST", f"{API}/datasets/{os.environ['ACTOR_DEFAULT_DATASET_ID']}/items", [item])
        print(f"apify_run: dataset -> {status} {str(body)[:120]}", flush=True)
    if os.environ.get("APIFY_TOKEN") and os.environ.get("ACTOR_DEFAULT_KEY_VALUE_STORE_ID"):
        status, body = _api("PUT", f"{API}/key-value-stores/{os.environ['ACTOR_DEFAULT_KEY_VALUE_STORE_ID']}/records/OUTPUT", item)
        print(f"apify_run: KV OUTPUT -> {status} {str(body)[:120]}", flush=True)


def serve() -> None:
    """Нет входа — работаем как MCP-сервер на порту платформы."""
    port = os.environ.get("ACTOR_WEB_SERVER_PORT") or os.environ.get("PORT") or "8192"
    here = os.path.dirname(os.path.abspath(__file__))
    cmd = [sys.executable, os.path.join(here, "mcp_server.py"), "--http", str(port),
           "--http-path", "/mcp", "--host", "0.0.0.0"]
    print(f"apify_run: входа нет -> MCP-сервер на порту {port}", flush=True)
    os.chdir(here)
    os.execv(cmd[0], cmd)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skilllint.linter import lint_skill  # noqa: E402

UA = "skilllint-apify/1.0"


def _fetch(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def run_action(inp: dict) -> dict:
    content = (inp.get("content") or "").strip()
    url = (inp.get("url") or "").strip()
    label = (inp.get("filename") or "").strip() or "skill"
    if not content and not url:
        raise ValueError("нужно поле content (текст SKILL.md) или url (ссылка на него)")
    if not content:
        content = _fetch(url)

    with tempfile.TemporaryDirectory() as tmp:
        d = os.path.join(tmp, label.replace("/", "_") or "skill")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(content)
        rep = lint_skill(os.path.join(d, "SKILL.md"))

    out = rep.as_dict()
    return {
        "skill": out.get("skill") or label,
        "verdict": out.get("verdict", "FAIL"),
        "score": int(out.get("score", 0)),
        "sha256": out.get("sha256", ""),
        "bytes": int(out.get("bytes", 0)),
        "findings": [
            {"rule": f.rule, "severity": f.severity, "message": f.message}
            for f in rep.findings
        ],
        "source_url": url,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "проверка выполнена локально внутри акта; наружу ничего не отправлялось",
    }


def main() -> int:
    inp = read_input()
    if not inp:
        serve()
        return 0
    try:
        item = run_action(inp)
    except Exception as e:  # noqa: BLE001
        item = {"error": f"{type(e).__name__}: {e}"}
    import json
    print(json.dumps(item, ensure_ascii=False, indent=2, default=str), flush=True)
    write_output(item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
