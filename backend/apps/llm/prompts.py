"""Prompts versionados: un archivo por versión, nunca se editan en sitio."""

import re
from functools import lru_cache
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
_COMMENTS = re.compile(r"<!--.*?-->", re.DOTALL)


@lru_cache(maxsize=32)
def load_prompt(task_dir, version):
    """Texto del prompt sin comentarios de mantenimiento."""
    path = PROMPTS_DIR / task_dir / f"{version}.md"
    if not path.is_file():
        raise FileNotFoundError(f"No existe el prompt {task_dir}/{version}.md")
    return _COMMENTS.sub("", path.read_text(encoding="utf-8")).strip()
