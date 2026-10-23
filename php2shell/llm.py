"""Pluggable LLM client (no SDKs, stdlib only).

Supported providers:
  * openai     - api.openai.com (also any OpenAI-compatible gateway via --llm-base-url)
  * anthropic  - api.anthropic.com
  * gemini     - generativelanguage.googleapis.com
  * mock       - offline, deterministic, for demos and tests

Keys are read from the environment first (PHP2SHELL_LLM_KEY, OPENAI_API_KEY,
ANTHROPIC_API_KEY, GEMINI_API_KEY) and otherwise asked for interactively. They
are never written to disk.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional

ENV_KEYS = {
    "openai": ("PHP2SHELL_LLM_KEY", "OPENAI_API_KEY"),
    "anthropic": ("PHP2SHELL_LLM_KEY", "ANTHROPIC_API_KEY"),
    "gemini": ("PHP2SHELL_LLM_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "mock": (),
}

DEFAULT_MODELS = {
    "openai": "gpt-5.1-mini",
    "anthropic": "claude-sonnet-4-6",
    "gemini": "gemini-2.5-pro",
    "mock": "mock-1",
}

BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
}


class LLMError(RuntimeError):
    pass


@dataclass
class LLMClient:
    provider: str = "openai"
    api_key: str = ""
    model: str = ""
    base_url: str = ""
    timeout: int = 180
    temperature: float = 0.1

    def __post_init__(self) -> None:
        self.provider = (self.provider or "openai").lower()
        if self.provider not in DEFAULT_MODELS:
            raise LLMError(
                f"unknown provider {self.provider!r}; choose from "
                + ", ".join(DEFAULT_MODELS)
            )
        self.model = self.model or DEFAULT_MODELS[self.provider]
        self.base_url = (self.base_url or BASE_URLS.get(self.provider, "")).rstrip("/")

    # -- key resolution ---------------------------------------------------
    @classmethod
    def resolve_key(cls, provider: str) -> Optional[str]:
        for var in ENV_KEYS.get(provider.lower(), ()):
            val = os.environ.get(var)
            if val:
                return val
        return None

    def validate(self) -> None:
        if self.provider == "mock":
            return
        if not self.api_key:
            raise LLMError(
                f"no API key for provider {self.provider!r}. Set "
                f"{ENV_KEYS[self.provider][0]} or pass --llm-key."
            )

    # -- public API -------------------------------------------------------
    def complete(self, system: str, user: str, max_tokens: int = 8000) -> str:
        self.validate()
        if self.provider == "mock":
            return _mock_complete(system, user)
        if self.provider == "openai":
            return self._openai(system, user, max_tokens)
        if self.provider == "anthropic":
            return self._anthropic(system, user, max_tokens)
        if self.provider == "gemini":
            return self._gemini(system, user, max_tokens)
        raise LLMError("unreachable")

    # -- providers --------------------------------------------------------
    def _post(self, url: str, payload: dict, headers: Dict[str, str]) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in headers.items():
            req.add_header(k, v)
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:800]
            except Exception:
                pass
            if exc.code == 401:
                raise LLMError("authentication failed (401). Check the API key.") from exc
            if exc.code == 429:
                raise LLMError("rate limited or out of quota (429).") from exc
            raise LLMError(f"HTTP {exc.code} from {url}: {body}") from exc
        except urllib.error.URLError as exc:
            raise LLMError(f"network error contacting {url}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise LLMError(f"provider returned non-JSON: {exc}") from exc

    def _openai(self, system: str, user: str, max_tokens: int) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": max_tokens,
        }
        data = self._post(
            f"{self.base_url}/chat/completions",
            payload,
            {"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"unexpected OpenAI response shape: {str(data)[:300]}") from exc

    def _anthropic(self, system: str, user: str, max_tokens: int) -> str:
        payload = {
            "model": self.model,
            "system": system,
            "max_tokens": max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": user}],
        }
        data = self._post(
            f"{self.base_url}/messages",
            payload,
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        try:
            blocks = data["content"]
            return "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        except (KeyError, TypeError) as exc:
            raise LLMError(f"unexpected Anthropic response shape: {str(data)[:300]}") from exc

    def _gemini(self, system: str, user: str, max_tokens: int) -> str:
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        data = self._post(
            f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}",
            payload,
            {},
        )
        try:
            cands = data["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in cands)
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected Gemini response shape: {str(data)[:300]}") from exc


# ---------------------------------------------------------------------------
# Offline mock so the tool is demonstrable without a key.
# ---------------------------------------------------------------------------
def _mock_complete(system: str, user: str) -> str:
    """Return a valid patch document without calling any API.

    It performs the deterministic parts of the remediation that a real model
    would normally produce: flipping the upload-progress flag, inserting the
    ini directive, bumping PHP pins inside a supported branch, and moving
    end-of-life branches onto the lowest supported fixed branch.
    """
    try:
        request = json.loads(user)
    except Exception:
        request = {}

    files = request.get("files", [])
    patches = []
    touched: List[str] = []

    for f in files:
        path = f.get("path", "")
        content = f.get("content", "")
        new = content

        if "upload_progress" in content:
            new = _mock_upload_progress(new)

        low = path.lower()
        if low.startswith("dockerfile") or low.endswith(".dockerfile") or low.endswith(
            ("docker-compose.yml", "docker-compose.yaml")
        ):
            new = _mock_docker_tag(new)

        if low == "composer.json":
            new = _mock_composer(new)

        if low.endswith((".yml", ".yaml")) and "php-version" in new:
            new = _mock_ci(new)

        if new != content:
            touched.append(path)
            patches.append({
                "path": path,
                "reason": "Deterministic remediation of the php2shell exposure: "
                          "upload-progress code path disabled and/or the PHP runtime "
                          "pinned to a fixed release "
                          "(8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).",
                "patched_content": new,
            })

    return json.dumps({
        "summary": (
            "Offline mock pass over " + (", ".join(touched) if touched else "no files") +
            ". Disabled session upload progress wherever it is configured and pinned "
            "PHP runtimes to a fixed release. End-of-life branches (8.1 and older) are "
            "moved to 8.2.35, the lowest branch that still receives upstream fixes - "
            "review that jump, and re-test extensions, before deploying."
        ),
        "patches": patches,
        "notes": [
            "mock provider: no LLM was called, these edits are rule-based",
            "use --llm-provider openai|anthropic|gemini for model-authored changes",
            "a major/minor runtime jump can change bundled extensions - test first",
        ],
    }, indent=2)


FIXED_FLAT = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
LOWEST_FIXED = "8.2.35"
EOL = {"5.4", "5.5", "5.6", "6.0", "7.0", "7.1", "7.2", "7.3", "7.4",
       "8.0", "8.1"}


def _resolve_target(version: str) -> Optional[str]:
    """Given a version-ish string, return the fixed version to use."""
    parts = version.split(".")
    if len(parts) < 2:
        return None
    branch = f"{parts[0]}.{parts[1]}"
    if branch in FIXED_FLAT:
        fixed = FIXED_FLAT[branch]
        if len(parts) == 3 and version >= fixed:
            return None          # already fine
        return fixed
    if branch in EOL:
        return LOWEST_FIXED
    return None


def _mock_docker_tag(text: str) -> str:
    """FROM php:8.1-apache -> FROM php:8.2.35-apache, keeping the suffix."""
    def repl(m: re.Match) -> str:
        prefix, version, suffix = m.group(1), m.group(2), m.group(3) or ""
        target = _resolve_target(version)
        if not target:
            return m.group(0)
        return f"{prefix}{target}{suffix}"

    pattern = re.compile(
        r"(FROM\s+(?:docker\.io/)?(?:library/)?php:)(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)([\w.\-]*)",
        re.I,
    )
    return pattern.sub(repl, text)


def _mock_composer(text: str) -> str:
    """'php': '>=7.4' -> 'php': '>=8.2.35' when the floor is affected."""
    def repl(m: re.Match) -> str:
        constraint = m.group(2)
        floor = re.search(r"(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)", constraint)
        if not floor:
            return m.group(0)
        target = _resolve_target(floor.group(1))
        if not target:
            return m.group(0)
        return f'{m.group(1)}">={target}"'

    return re.sub(r'("php(?:-64bit)?"\s*:\s*)("[^"]*")', repl, text)


def _mock_ci(text: str) -> str:
    def repl(m: re.Match) -> str:
        target = _resolve_target(m.group(2))
        if not target:
            return m.group(0)
        return f"{m.group(1)}{target}"

    return re.sub(r"(php-version:\s*['\"]?)(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)", repl, text)


def _mock_upload_progress(text: str) -> str:
    out = re.sub(
        r"^(\s*session\.upload_progress\.enabled\s*=\s*)(On|1|true|yes|on)\b",
        r"\1Off",
        text,
        flags=re.I | re.M,
    )
    if "session.upload_progress.enabled" not in out:
        out = out.rstrip("\n") + (
            "\n\n; php2shell interim mitigation (CVE-2026-109618 / CVE-2026-109619)\n"
            "session.upload_progress.enabled = Off\n"
        )
    return out


def parse_patch_json(raw: str) -> dict:
    """LLMs love to wrap JSON in prose or fences. Salvage what we can."""
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        for part in parts:
            candidate = part.strip()
            if candidate.startswith("{"):
                text = candidate
                break
            if candidate.lower().startswith("json"):
                text = candidate[4:].strip()
                break
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {}
