from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.config import bundled_rules_dir, user_rules_dir

_RULE_SPLIT = re.compile(r"(?m)^rule\s+([A-Za-z0-9_]+)\s*\{")
_META = re.compile(r'(?m)^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]*)"')
_STR_TEXT = re.compile(r'(?m)^\s*(\$[A-Za-z0-9_]+)\s*=\s*"((?:\\.|[^"\\])*)"([^\n]*)')
_STR_HEX = re.compile(r"(?m)^\s*(\$[A-Za-z0-9_]+)\s*=\s*\{([^}]+)\}")


@dataclass
class YaraString:
    ident: str
    value: bytes
    nocase: bool = False


@dataclass
class CompiledRule:
    name: str
    meta: dict[str, str] = field(default_factory=dict)
    strings: list[YaraString] = field(default_factory=list)
    condition: str = ""


def _unescape(text: str) -> bytes:
    return bytes(text.encode("utf-8").decode("unicode_escape"), "latin-1")


def _parse_hex(blob: str) -> bytes:
    hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", blob)
    return bytes(int(h, 16) for h in hex_bytes)


def parse_yar_source(source: str) -> list[CompiledRule]:
    matches = list(_RULE_SPLIT.finditer(source))
    rules: list[CompiledRule] = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(source)
        body = source[start:end]
        # drop trailing closing brace of the rule
        body = body.rsplit("}", 1)[0]
        meta_block = _section(body, "meta")
        strings_block = _section(body, "strings")
        condition_block = _section(body, "condition")
        meta = dict(_META.findall(meta_block))
        strings: list[YaraString] = []
        for ident, text, flags in _STR_TEXT.findall(strings_block):
            strings.append(
                YaraString(
                    ident=ident,
                    value=_unescape(text),
                    nocase="nocase" in flags.lower(),
                )
            )
        for ident, hexblob in _STR_HEX.findall(strings_block):
            strings.append(YaraString(ident=ident, value=_parse_hex(hexblob)))
        rules.append(
            CompiledRule(
                name=match.group(1),
                meta=meta,
                strings=strings,
                condition=condition_block.strip().rstrip("}"),
            )
        )
    return rules


def _section(body: str, name: str) -> str:
    pattern = re.compile(rf"(?ms)^\s*{name}\s*:(.*?)(?=^\s*(?:meta|strings|condition)\s*:|\Z)")
    found = pattern.search(body)
    return found.group(1) if found else ""


def load_rules(extra_dirs: list[Path] | None = None) -> list[CompiledRule]:
    dirs = [bundled_rules_dir(), user_rules_dir()]
    if extra_dirs:
        dirs.extend(extra_dirs)
    seen: set[Path] = set()
    rules: list[CompiledRule] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        resolved = directory.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        for path in sorted(directory.glob("*.yar")):
            rules.extend(parse_yar_source(path.read_text(encoding="utf-8", errors="ignore")))
        for path in sorted(directory.glob("*.yara")):
            rules.extend(parse_yar_source(path.read_text(encoding="utf-8", errors="ignore")))
    return rules


def _string_hits(rule: CompiledRule, data: bytes) -> dict[str, bool]:
    hits: dict[str, bool] = {}
    for item in rule.strings:
        if item.nocase:
            hits[item.ident] = item.value.lower() in data.lower()
        else:
            hits[item.ident] = item.value in data
    return hits


def _eval_condition(condition: str, hits: dict[str, bool]) -> bool:
    text = condition.strip()
    if not text:
        return any(hits.values()) if hits else False
    if text in {"any of them", "any of them()"}:
        return any(hits.values())
    if text in {"all of them", "all of them()"}:
        return bool(hits) and all(hits.values())
    of_n = re.match(r"(\d+)\s+of\s+them", text)
    if of_n:
        return sum(1 for v in hits.values() if v) >= int(of_n.group(1))
    # Replace identifiers with True/False and evaluate a boolean expression.
    expr = text
    for ident, matched in sorted(hits.items(), key=lambda kv: len(kv[0]), reverse=True):
        expr = expr.replace(ident, "True" if matched else "False")
    expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace(" not ", " not ")
    expr = re.sub(r"\$[A-Za-z0-9_]+", "False", expr)
    if not re.fullmatch(r"(?:True|False|and|or|not|[()\s])+", expr):
        return any(hits.values())
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return any(hits.values())


def match_bytes(data: bytes, rules: list[CompiledRule] | None = None) -> list[dict[str, Any]]:
    compiled = rules if rules is not None else load_rules()
    results: list[dict[str, Any]] = []
    for rule in compiled:
        hits = _string_hits(rule, data)
        if _eval_condition(rule.condition, hits):
            matched = [ident for ident, ok in hits.items() if ok]
            results.append(
                {
                    "rule": rule.name,
                    "meta": rule.meta,
                    "strings": matched,
                }
            )
    return results


def match_file(path: Path, rules: list[CompiledRule] | None = None, max_bytes: int = 12 * 1024 * 1024) -> list[dict[str, Any]]:
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    return match_bytes(data, rules)
