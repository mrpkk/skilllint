"""skilllint — пакет линтера скиллов агента."""
from .linter import RULES, Report, compare, lint_skill, rules  # noqa: F401

__all__ = ["lint_skill", "compare", "rules", "RULES", "Report"]
__version__ = "1.0.0"
