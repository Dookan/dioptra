"""Language, framework and lockfile detection over the extracted tree.

Deterministic and cheap: extension counts for languages, manifest inspection
for frameworks, file names for lockfiles. Nothing is executed or imported.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

EXTENSION_LANGUAGES: dict[str, str] = {
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".py": "Python",
    ".php": "PHP",
    ".java": "Java",
    ".go": "Go",
    ".cs": "C#",
    ".rb": "Ruby",
    ".html": "HTML",
    ".css": "CSS",
    ".sql": "SQL",
}

LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "composer.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "go.sum",
        "Gemfile.lock",
        "packages.lock.json",
    }
)

SKIPPED_DIRS: frozenset[str] = frozenset(
    {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next"}
)

# Framework markers: dependency name → display name, per manifest kind.
NPM_FRAMEWORKS: dict[str, str] = {
    "express": "Express",
    "@nestjs/core": "NestJS",
    "next": "Next.js",
    "react": "React",
    "vue": "Vue",
    "@angular/core": "Angular",
    "fastify": "Fastify",
    "koa": "Koa",
    "hapi": "hapi",
    "@hapi/hapi": "hapi",
    "svelte": "Svelte",
}
PYTHON_FRAMEWORKS: dict[str, str] = {
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "tornado": "Tornado",
    "aiohttp": "aiohttp",
}
PHP_FRAMEWORKS: dict[str, str] = {
    "laravel/framework": "Laravel",
    "symfony/symfony": "Symfony",
    "symfony/framework-bundle": "Symfony",
    "slim/slim": "Slim",
    "codeigniter4/framework": "CodeIgniter",
}
JAVA_MARKERS: dict[str, str] = {
    "spring-boot": "Spring Boot",
    "org.springframework": "Spring",
    "quarkus": "Quarkus",
    "micronaut": "Micronaut",
}

MAX_FILES_SCANNED = 200_000
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass
class Detection:
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)


def _walk(root: Path) -> list[Path]:
    """Files under root, never following symlinks, bounded in count."""
    found: list[Path] = []
    stack = [root]
    while stack and len(found) < MAX_FILES_SCANNED:
        current = stack.pop()
        try:
            children = sorted(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name not in SKIPPED_DIRS:
                    stack.append(child)
            elif child.is_file():
                found.append(child)
                if len(found) >= MAX_FILES_SCANNED:
                    break
    return found


def _read_small(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _frameworks_from_package_json(text: str) -> set[str]:
    try:
        manifest = json.loads(text)
    except ValueError:
        return set()
    if not isinstance(manifest, dict):
        return set()
    names: set[str] = set()
    for key in ("dependencies", "devDependencies"):
        section = manifest.get(key)
        if isinstance(section, dict):
            names.update(str(name) for name in section)
    return {NPM_FRAMEWORKS[name] for name in names if name in NPM_FRAMEWORKS}


def _frameworks_from_requirements(text: str) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        match = _REQUIREMENT_NAME.match(line)
        if match:
            name = match.group(1).lower().replace("_", "-")
            if name in PYTHON_FRAMEWORKS:
                found.add(PYTHON_FRAMEWORKS[name])
    return found


def _frameworks_from_pyproject(text: str) -> set[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return set()
    deps: list[str] = []
    project = data.get("project")
    if isinstance(project, dict) and isinstance(project.get("dependencies"), list):
        deps.extend(str(item) for item in project["dependencies"])
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
            deps.extend(str(name) for name in poetry["dependencies"])
    return _frameworks_from_requirements("\n".join(deps))


def _frameworks_from_composer(text: str) -> set[str]:
    try:
        manifest = json.loads(text)
    except ValueError:
        return set()
    if not isinstance(manifest, dict):
        return set()
    names: set[str] = set()
    for key in ("require", "require-dev"):
        section = manifest.get(key)
        if isinstance(section, dict):
            names.update(str(name).lower() for name in section)
    return {PHP_FRAMEWORKS[name] for name in names if name in PHP_FRAMEWORKS}


def _frameworks_from_java(text: str) -> set[str]:
    return {label for marker, label in JAVA_MARKERS.items() if marker in text}


def detect(root: Path) -> Detection:
    """Inspect the extracted tree. Pure function of the file system."""
    result = Detection()
    frameworks: set[str] = set()
    for path in _walk(root):
        suffix = path.suffix.lower()
        language = EXTENSION_LANGUAGES.get(suffix)
        if language:
            result.languages[language] = result.languages.get(language, 0) + 1
        name = path.name
        relative = path.relative_to(root).as_posix()
        if name in LOCKFILE_NAMES:
            result.lockfiles.append(relative)
        if name == "package.json":
            text = _read_small(path)
            if text:
                frameworks |= _frameworks_from_package_json(text)
        elif name == "requirements.txt":
            text = _read_small(path)
            if text:
                frameworks |= _frameworks_from_requirements(text)
        elif name == "pyproject.toml":
            text = _read_small(path)
            if text:
                frameworks |= _frameworks_from_pyproject(text)
        elif name == "composer.json":
            text = _read_small(path)
            if text:
                frameworks |= _frameworks_from_composer(text)
        elif name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            text = _read_small(path)
            if text:
                frameworks |= _frameworks_from_java(text)
    result.frameworks = sorted(frameworks)
    result.lockfiles.sort()
    result.languages = dict(sorted(result.languages.items(), key=lambda item: (-item[1], item[0])))
    return result
