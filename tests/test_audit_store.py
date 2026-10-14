import csv
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

from controlled_compare.audit_store import export_dashboard, import_jsonl


ROOT = Path(__file__).resolve().parents[1]
EDGE_CASES_JSONL = ROOT / "outputs" / "audit_trace_edge_cases.jsonl"


class AuditStoreImportTests(unittest.TestCase):
    def test_import_jsonl_counts_all_edge_case_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "audit.db"

            imported_count = import_jsonl(EDGE_CASES_JSONL, db_path)

            with sqlite3.connect(db_path) as connection:
                stored_count = connection.execute(
                    "SELECT COUNT(*) FROM audit_runs"
                ).fetchone()[0]

        self.assertEqual(imported_count, 5)
        self.assertEqual(stored_count, 5)

    def test_duplicate_unique_key_is_reported_or_counted_consistently(self) -> None:
        record = EDGE_CASES_JSONL.read_text(encoding="utf-8").splitlines()[0]

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_directory_path = Path(temporary_directory)
            jsonl_path = temporary_directory_path / "duplicate.jsonl"
            db_path = temporary_directory_path / "audit.db"
            jsonl_path.write_text(f"{record}\n{record}\n", encoding="utf-8")

            with warnings.catch_warnings(record=True) as caught_warnings:
                warnings.simplefilter("always")
                try:
                    imported_count = import_jsonl(jsonl_path, db_path)
                except Exception:
                    return

            with sqlite3.connect(db_path) as connection:
                stored_count = connection.execute(
                    "SELECT COUNT(*) FROM audit_runs"
                ).fetchone()[0]

        self.assertTrue(
            caught_warnings or imported_count == stored_count,
            "duplicate unique key was silently replaced: "
            f"import_jsonl returned {imported_count}, database has {stored_count}",
        )

    def test_audit_views_group_edge_case_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            db_path = Path(temporary_directory) / "audit.db"

            import_jsonl(EDGE_CASES_JSONL, db_path)

            with sqlite3.connect(db_path) as connection:
                view_counts = {
                    view_name: connection.execute(
                        f"SELECT COUNT(*) FROM {view_name}"
                    ).fetchone()[0]
                    for view_name in (
                        "v_decision_by_arm",
                        "v_failure_by_category",
                        "v_cost_by_arm",
                    )
                }

        self.assertEqual(view_counts["v_decision_by_arm"], 4)
        self.assertEqual(view_counts["v_failure_by_category"], 3)
        self.assertEqual(view_counts["v_cost_by_arm"], 2)

    def test_dashboard_exports_decision_distribution_html(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_directory_path = Path(temporary_directory)
            db_path = temporary_directory_path / "audit.db"
            html_path = temporary_directory_path / "dashboard.html"

            import_jsonl(EDGE_CASES_JSONL, db_path)
            export_dashboard(db_path, html_path)

            self.assertTrue(html_path.exists())
            html = html_path.read_text(encoding="utf-8")

        self.assertIsInstance(html, str)
        self.assertTrue(html)
        for expected in (
            "single-hold=2",
            "single-deny=1",
            "multi-hold=1",
            "multi-permit=1",
            "infrastructure-retriable=1",
            "model_contract-non-retriable=1",
            "none-non-retriable=3",
            "multi-runs=2",
            "single-runs=3",
            "multi-tokens=3002",
            "single-tokens=1356",
            "multi-calls=5",
            "single-calls=2",
            "multi-cost_cny=0.0154",
            "single-cost_cny=0.0069",
        ):
            self.assertIn(expected, html)

    def test_dashboard_uses_shared_svg_layout_and_decimal_cost_axis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_directory_path = Path(temporary_directory)
            db_path = temporary_directory_path / "audit.db"
            html_path = temporary_directory_path / "dashboard.html"

            import_jsonl(EDGE_CASES_JSONL, db_path)
            export_dashboard(db_path, html_path)
            html = html_path.read_text(encoding="utf-8")

        svg_openings = [
            line for line in html.splitlines() if '<svg ' in line
        ]
        self.assertEqual(len(svg_openings), 6)
        self.assertTrue(
            all(
                'width="760" height="500" viewBox="0 0 760 500"' in line
                for line in svg_openings
            )
        )
        cost_chart = html.split(
            'aria-labelledby="cost-cost_cny-chart-title', 1
        )[1]
        self.assertIn(">0.02</text>", cost_chart)

    def test_report_exports_all_audit_views_without_raw_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_directory_path = Path(temporary_directory)
            db_path = temporary_directory_path / "audit.db"
            output_directory = temporary_directory_path / "report"
            import_jsonl(EDGE_CASES_JSONL, db_path)

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "controlled_compare.audit_store",
                    "report",
                    str(db_path),
                    str(output_directory),
                ],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            expected_rows = {
                "view_decision_by_arm.csv": 4,
                "view_failure_by_category.csv": 3,
                "view_cost_by_arm.csv": 2,
            }
            for filename, expected_row_count in expected_rows.items():
                report_path = output_directory / filename
                self.assertTrue(report_path.exists())
                with report_path.open(newline="", encoding="utf-8") as report:
                    rows = list(csv.reader(report))
                self.assertEqual(len(rows) - 1, expected_row_count)
                self.assertNotIn("raw_trace", rows[0])


if __name__ == "__main__":
    unittest.main()
