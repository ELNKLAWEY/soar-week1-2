"""Minimal YAML playbook engine with dry-run (M1 Week 1–2)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


_VAR = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def _lookup(path: str, ctx: dict[str, Any]) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def render(value: Any, ctx: dict[str, Any]) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            found = _lookup(match.group(1), ctx)
            return "" if found is None else str(found)

        return _VAR.sub(repl, value)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


def eval_when(expr: str | None, ctx: dict[str, Any]) -> bool:
    if not expr:
        return True
    # Small subset: path == "value" / path == 'value', or truthiness of a path.
    # Support both quote styles (YAML may preserve either after load).
    eq = re.match(r"""([\w.]+)\s*==\s*(?:"([^"]*)"|'([^']*)')""", expr.strip())
    if eq:
        left = _lookup(eq.group(1), ctx)
        expected = eq.group(2) if eq.group(2) is not None else eq.group(3)
        return str(left) == expected
    val = _lookup(expr.strip(), ctx)
    return bool(val)


@dataclass
class StepResult:
    id: str
    action: str
    skipped: bool
    dry_run: bool
    args: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybookRun:
    name: str
    dry_run: bool
    steps: list[StepResult] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


class PlaybookEngine:
    def load(self, path: str | Path) -> dict[str, Any]:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "name" not in data or "steps" not in data:
            raise ValueError("playbook must have name and steps")
        return data

    def run(
        self,
        playbook: dict[str, Any],
        context: dict[str, Any] | None = None,
        *,
        dry_run: bool = True,
        action_handler=None,
    ) -> PlaybookRun:
        ctx = dict(context or {})
        run = PlaybookRun(name=playbook["name"], dry_run=dry_run, context=ctx)

        for step in playbook.get("steps", []):
            sid = step["id"]
            action = step["action"]
            when = step.get("when")
            if not eval_when(when, ctx):
                run.steps.append(
                    StepResult(id=sid, action=action, skipped=True, dry_run=dry_run)
                )
                continue

            args = render(step.get("args") or {}, ctx)
            output: dict[str, Any]
            if dry_run or action_handler is None:
                output = {"would_call": action, "args": args}
            else:
                output = action_handler(action, args) or {}

            # Merge into existing context for this step id so pre-seeded
            # inputs (e.g. decide.verdict) are not wiped by dry-run stubs.
            existing = ctx.get(sid)
            if isinstance(existing, dict) and isinstance(output, dict):
                merged = dict(existing)
                merged.update(output)
                ctx[sid] = merged
            else:
                ctx[sid] = output
            run.steps.append(
                StepResult(
                    id=sid,
                    action=action,
                    skipped=False,
                    dry_run=dry_run,
                    args=args,
                    output=output,
                )
            )
        run.context = ctx
        return run
