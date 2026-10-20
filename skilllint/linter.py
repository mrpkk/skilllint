"""skilllint — линтер качества и безопасности скиллов агента (SKILL.md).

Приватный по построению: проверка идёт локально, содержимое наружу не уходит.
Не копия NVIDIA SkillSpector (тот — 71 паттерн, AST/YARA/CVE): наша ниша —
структура и триггеры, приватность, воспроизводимость вердикта, сравнение
кандидатов. Основание: `docs/EVIDENCE.md` (F-01…F-08, I-01…I-05).
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field

MAX_BYTES = 60_000
MAX_DESC = 1024

RULES: list[dict] = [
    {"id": "R-001", "severity": "critical", "title": "нет frontmatter"},
    {"id": "R-002", "severity": "high", "title": "нет корректного name"},
    {"id": "R-003", "severity": "high", "title": "description отсутствует или слишком длинный"},
    {"id": "R-004", "severity": "medium", "title": "нет триггера в description"},
    {"id": "R-005", "severity": "medium", "title": "мёртвые инструкции (TODO/deprecated)"},
    {"id": "R-006", "severity": "critical", "title": "похожие на секреты литералы"},
    {"id": "R-007", "severity": "critical", "title": "маркеры prompt-injection / exfiltration"},
    {"id": "R-008", "severity": "medium", "title": "ссылки на несуществующие файлы"},
    {"id": "R-009", "severity": "low", "title": "файл больше 60 КБ"},
    {"id": "R-010", "severity": "high", "title": "скрипты доступны на запись всем"},
    {"id": "R-011", "severity": "medium", "title": "неограниченная автономия в инструкциях"},
]

SEVERITY_PENALTY = {"critical": 25, "high": 10, "medium": 5, "low": 2}

TRIGGER_CUES = ("когда", "использовать", "используй", "для чего", "use when", "load when",
                "apply when", "загрузи", "подходит для", "triggers", "when to use",
                "use this when", "for when", "invoke when")
DEAD_MARKERS = ("todo", "fixme", "не работает", "deprecated", "устарел", "временно отключ",
                "не реализовано", "заглушка", "placeholder")
SECRET_PATTERNS = [
    r"\bsk-[A-Za-z0-9]{16,}", r"\bghp_[A-Za-z0-9]{20,}", r"\bgithub_pat_[A-Za-z0-9_]{20,}",
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}", r"\bAKIA[0-9A-Z]{16}\b",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
]
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)",
    r"disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)",
    r"forget\s+(?:everything|all)\s+(?:you|your|previous)",
    r"(?:send|post|upload|exfiltrate)\s+(?:the\s+|your\s+|all\s+)?(?:contents?|data|keys?|secrets?|credentials?)\s+to\s+https?://",
    r"(?:reveal|print|show|output|repeat)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|api[_ ]?key|secret|token|credential)",
    r"you\s+are\s+now\s+(?:a|an|in)\s+\w+",
]
AUTONOMY_PATTERNS = [
    r"without\s+(?:asking|confirmation|approval)", r"never\s+ask\s+(?:the\s+)?(?:user|permission)",
    r"без\s+(?:подтверждения|спроса|разрешения)", r"не\s+спрашивай", r"автоматически\s+примени",
    r"do\s+not\s+(?:ask|prompt)\b",
]
FILE_REF = re.compile(r"`([^`\n]+\.(?:md|py|sh|json|yaml|yml|toml|txt))`|\]\(([^)\n]+)\)")


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    line: int | None = None

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "message": self.message, "line": self.line}


@dataclass
class Report:
    skill: str
    path: str
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    sha256: str = ""
    bytes: int = 0
    name: str = ""

    def as_dict(self) -> dict:
        return {
            "skill": self.name or self.skill,
            "path": self.path,
            "score": self.score,
            "verdict": self.verdict,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "findings": [f.as_dict() for f in self.findings],
        }


def _parse_frontmatter(text: str) -> tuple[dict, str, int]:
    """Возвращает (frontmatter, body, offset_строк_body)."""
    if not text.startswith("---"):
        return {}, text, 0
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text, 0
    raw = text[3:end]
    body = text[end + 4:]
    fm: dict[str, str] = {}
    for line in raw.splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line.strip())
        if m:
            fm[m.group(1).lower()] = m.group(2).strip().strip("'\"")
    return fm, body, raw.count("\n") + 2




def _is_citation(text: str, pos: int) -> bool:
    """Совпадение внутри кавычек — это цитата примера, а не директива."""
    line_start = text.rfind("\n", 0, pos) + 1
    prefix = text[line_start:pos]
    return prefix.count('"') % 2 == 1 or prefix.count("'") % 2 == 1

def _prose_only(text: str) -> str:
    """Текст без строк markdown-таблиц и без блоков кода — только проза инструкций."""
    out, in_fence = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or stripped.startswith("|"):
            continue
        out.append(line)
    return "\n".join(out)

def _line_of(body: str, offset: int, needle: str) -> int | None:
    idx = body.find(needle)
    if idx == -1:
        return None
    return body[:idx].count("\n") + offset + 1


def lint_skill(path: str) -> Report:
    """Проверить один SKILL.md. Возвращает вердикт с хешем (воспроизводимо)."""
    p = os.path.abspath(os.path.expanduser(path))
    rep = Report(skill=os.path.basename(os.path.dirname(p)) or os.path.basename(p), path=p, score=100, verdict="PASS")
    if os.path.isdir(p):
        cand = os.path.join(p, "SKILL.md")
        p = cand
        rep.path = cand
        rep.skill = os.path.basename(os.path.dirname(cand))
    if not os.path.exists(p):
        rep.score = 0
        rep.verdict = "FAIL"
        rep.findings.append(Finding("R-000", "critical", "file not found"))
        return rep
    data = open(p, "rb").read()
    rep.bytes = len(data)
    rep.sha256 = hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8", "replace")
    fm, body, off = _parse_frontmatter(text)

    if not fm:
        rep.findings.append(Finding("R-001", "critical", "frontmatter (--- ... ---) not found"))
    name = fm.get("name", "")
    desc = fm.get("description", "")
    rep.name = name
    if not name or not re.match(r"^[a-z0-9][a-z0-9-]*$", name):
        rep.findings.append(Finding("R-002", "high", f"name is missing or malformed: {name!r}"))
    if not desc:
        rep.findings.append(Finding("R-003", "high", "description is missing"))
    elif len(desc) > MAX_DESC:
        rep.findings.append(Finding("R-003", "high", f"description is longer than {MAX_DESC} characters ({len(desc)})"))
    if desc and not any(c in desc.lower() for c in TRIGGER_CUES):
        rep.findings.append(Finding("R-004", "medium", "no trigger wording in the description (nothing says when to use it)"))

    low = text.lower()
    for mk in DEAD_MARKERS:
        if mk in low:
            rep.findings.append(Finding("R-005", "medium", f"dead marker: {mk!r}", _line_of(text, 0, mk)))
            break

    for pat in SECRET_PATTERNS:
        m = re.search(pat, text)
        if m:
            rep.findings.append(Finding("R-006", "critical", f"secret-like literal: {m.group(0)[:12]}…", _line_of(text, 0, m.group(0))))
            break

    for pat in INJECTION_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            rep.findings.append(Finding("R-007", "critical", f"injection/exfiltration marker: {m.group(0)[:40]}", _line_of(text, 0, m.group(0))))
            break

    base = os.path.dirname(p)
    for m in FILE_REF.finditer(text):
        ref = (m.group(1) or m.group(2) or "").strip()
        if not ref or ref.startswith(("http://", "https://", "#", "mailto:")):
            continue
        target = os.path.normpath(os.path.join(base, ref))
        if not os.path.exists(target):
            rep.findings.append(Finding("R-008", "medium", f"referenced file not found: {ref}"))
            break

    if rep.bytes > MAX_BYTES:
        rep.findings.append(Finding("R-009", "low", f"file size {rep.bytes} bytes > {MAX_BYTES}"))

    for root, _dirs, files in os.walk(base):
        for f in files:
            if f.endswith((".py", ".sh")):
                fp = os.path.join(root, f)
                try:
                    mode = os.stat(fp).st_mode
                except OSError:
                    continue
                if mode & 0o002:
                    rep.findings.append(Finding("R-010", "high", f"file is writable by everyone: {os.path.relpath(fp, base)}"))
                    break

    # Инструкции смотрим вне таблиц и вне блоков кода: скилл, который
    # перечисляет правила, не должен ловиться за собственное описание правил.
    prose = _prose_only(text)
    for pat in AUTONOMY_PATTERNS:
        m = re.search(pat, prose, re.I)
        if m and _is_citation(prose, m.start()):
            continue  # фраза процитирована (пример в кавычках), а не дана как инструкция
        if m:
            rep.findings.append(Finding("R-011", "medium", f"unbounded autonomy: {m.group(0)[:40]}", _line_of(text, 0, m.group(0))))
            break

    score = 100
    for f in rep.findings:
        score -= SEVERITY_PENALTY.get(f.severity, 2)
    rep.score = max(0, score)
    if any(f.severity == "critical" for f in rep.findings):
        rep.verdict = "FAIL"
    elif rep.score < 80 or any(f.severity == "high" for f in rep.findings):
        rep.verdict = "WARN"
    else:
        rep.verdict = "PASS"
    return rep


def compare(paths: list[str]) -> list[dict]:
    """Сравнить кандидатов: ранжирование по вердикту и доказательной базе."""
    reports = [lint_skill(p) for p in paths]
    reports.sort(key=lambda r: (r.verdict != "PASS", -r.score, len(r.findings)))
    return [r.as_dict() for r in reports]


def rules() -> list[dict]:
    return RULES
