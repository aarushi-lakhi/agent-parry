"""Attack scanner that replays payloads through the proxy."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.models import (
    PROXY_URL,
    AttackPayload,
    AttackResult,
    ScanReport,
)

console = Console()


class Scanner:
    """Loads attack payloads from YAML and fires them at the proxy."""

    def __init__(self, payloads_path: str = "attacks/payloads.yaml") -> None:
        with open(payloads_path) as f:
            data = yaml.safe_load(f)
        self.payloads: list[AttackPayload] = [
            AttackPayload(**entry) for entry in data.get("payloads", [])
        ]

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------

    async def run_scan(
        self, proxy_url: str = PROXY_URL
    ) -> ScanReport:
        results: list[AttackResult] = []
        blocked = 0
        redacted = 0
        passed = 0

        async with httpx.AsyncClient(timeout=10.0) as client:
            for idx, payload in enumerate(self.payloads, start=1):
                rpc_request: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": payload.tool,
                        "arguments": payload.arguments,
                    },
                    "id": idx,
                }

                try:
                    resp = await client.post(proxy_url, json=rpc_request)
                    body = resp.json()
                except httpx.HTTPError as exc:
                    results.append(
                        AttackResult(
                            payload=payload,
                            passed_through=True,
                            notes=f"Connection error: {exc}",
                        )
                    )
                    passed += 1
                    continue

                result = self._classify_response(payload, body)
                results.append(result)

                if result.was_blocked:
                    blocked += 1
                elif result.was_redacted:
                    redacted += 1
                else:
                    passed += 1

        total = len(self.payloads)
        score = round((passed / total) * 100, 1) if total else 0.0

        return ScanReport(
            total_attacks=total,
            blocked=blocked,
            passed=passed,
            redacted=redacted,
            results=results,
            vulnerability_score=score,
            timestamp=datetime.now(timezone.utc),
        )

    async def run_rescan(
        self, proxy_url: str, original_report: ScanReport
    ) -> ScanReport:
        vulnerable_payloads = [
            r.payload for r in original_report.results if r.passed_through
        ]

        results: list[AttackResult] = []
        blocked = 0
        redacted = 0
        passed = 0

        async with httpx.AsyncClient(timeout=10.0) as client:
            for idx, payload in enumerate(vulnerable_payloads, start=1):
                rpc_request: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": payload.tool,
                        "arguments": payload.arguments,
                    },
                    "id": idx,
                }

                try:
                    resp = await client.post(proxy_url, json=rpc_request)
                    body = resp.json()
                except httpx.HTTPError as exc:
                    results.append(
                        AttackResult(
                            payload=payload,
                            passed_through=True,
                            notes=f"Connection error: {exc}",
                        )
                    )
                    passed += 1
                    continue

                result = self._classify_response(payload, body)
                results.append(result)

                if result.was_blocked:
                    blocked += 1
                elif result.was_redacted:
                    redacted += 1
                else:
                    passed += 1

        total = len(vulnerable_payloads)
        score = round((passed / total) * 100, 1) if total else 0.0

        return ScanReport(
            total_attacks=total,
            blocked=blocked,
            passed=passed,
            redacted=redacted,
            results=results,
            vulnerability_score=score,
            timestamp=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def print_report(self, report: ScanReport) -> None:
        summary = (
            f"Scanned {report.total_attacks} attacks | "
            f"{report.blocked} blocked | "
            f"{report.redacted} redacted | "
            f"{report.passed} PASSED THROUGH"
        )

        score_text = self._score_text(report.vulnerability_score)

        console.print()
        console.print(
            Panel(
                f"{summary}\n\nVulnerability Score: {score_text}",
                title="[bold]AgentParry Scan Report[/bold]",
                expand=False,
            )
        )

        sorted_results = sorted(
            report.results, key=lambda r: not r.passed_through
        )

        table = Table(show_lines=True)
        table.add_column("Status", justify="center")
        table.add_column("Severity", justify="center")
        table.add_column("Category")
        table.add_column("Attack Name")
        table.add_column("Tool")
        table.add_column("Notes")

        for r in sorted_results:
            status = self._status_cell(r)
            sev = r.payload.severity.upper()
            table.add_row(
                status,
                sev,
                r.payload.category,
                r.payload.name,
                r.payload.tool,
                r.notes,
            )

        console.print(table)
        console.print()

    def print_comparison(
        self, before: ScanReport, after: ScanReport
    ) -> None:
        before_score = self._score_text(before.vulnerability_score)
        after_score = self._score_text(after.vulnerability_score)

        console.print()
        console.print(f"BEFORE: vulnerability score {before_score}")
        console.print(f"AFTER:  vulnerability score {after_score}")
        console.print()

        after_lookup: dict[str, AttackResult] = {
            r.payload.id: r for r in after.results
        }

        table = Table(title="Status Changes", show_lines=True)
        table.add_column("Attack Name")
        table.add_column("Before", justify="center")
        table.add_column("After", justify="center")

        fixed = 0
        total_vulnerable = sum(
            1 for r in before.results if r.passed_through
        )

        for r_before in before.results:
            if not r_before.passed_through:
                continue
            r_after = after_lookup.get(r_before.payload.id)
            if r_after is None:
                continue

            before_status = self._status_cell(r_before)
            after_status = self._status_cell(r_after)

            if not r_after.passed_through:
                fixed += 1

            table.add_row(r_before.payload.name, before_status, after_status)

        console.print(table)
        console.print(
            f"\nFixed {fixed} of {total_vulnerable} vulnerabilities\n"
        )

    def save_report(
        self, report: ScanReport, path: str = "reports/"
    ) -> str:
        out_dir = Path(path)
        out_dir.mkdir(parents=True, exist_ok=True)

        ts = report.timestamp.strftime("%Y-%m-%dT%H-%M-%S")
        filename = out_dir / f"scan_{ts}.json"

        data = report.model_dump(mode="json")
        filename.write_text(json.dumps(data, indent=2))

        return str(filename)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_response(
        payload: AttackPayload, body: dict[str, Any]
    ) -> AttackResult:
        if "error" in body and body["error"] is not None:
            return AttackResult(
                payload=payload,
                was_blocked=True,
                proxy_response=body,
                notes="Blocked by proxy",
            )

        result_value = body.get("result")
        if isinstance(result_value, str) and "[REDACTED" in result_value:
            return AttackResult(
                payload=payload,
                was_redacted=True,
                proxy_response=body,
                notes="Output redacted by proxy",
            )
        if isinstance(result_value, dict):
            for v in result_value.values():
                if isinstance(v, str) and "[REDACTED" in v:
                    return AttackResult(
                        payload=payload,
                        was_redacted=True,
                        proxy_response=body,
                        notes="Output redacted by proxy",
                    )

        return AttackResult(
            payload=payload,
            passed_through=True,
            proxy_response=body,
            notes="Passed through unblocked",
        )

    @staticmethod
    def _score_text(score: float) -> Text:
        if score <= 20:
            return Text(f"{score}% — SECURE", style="bold green")
        if score <= 50:
            return Text(f"{score}% — MODERATE RISK", style="bold yellow")
        if score <= 80:
            return Text(f"{score}% — HIGH RISK", style="bold red")
        return Text(f"{score}% — CRITICAL", style="bold red underline")

    @staticmethod
    def _status_cell(result: AttackResult) -> Text:
        if result.was_blocked:
            return Text("[+] BLOCKED", style="green")
        if result.was_redacted:
            return Text("[~] REDACTED", style="blue")
        return Text("[!] VULNERABLE", style="red")
