"""Local audit store for v0.4 JSONL traces.

The JSONL file remains the immutable export. SQLite is a derived, queryable
index for local review and later reporting/BI ingestion.
"""

from __future__ import annotations

import argparse
import csv
from html import escape
import json
import math
import sqlite3
import warnings
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_runs (
    id INTEGER PRIMARY KEY,
    protocol_version TEXT NOT NULL,
    dataset TEXT NOT NULL,
    evaluation_valid INTEGER NOT NULL,
    case_id TEXT NOT NULL,
    repetition INTEGER,
    arm TEXT NOT NULL,
    response_usable INTEGER NOT NULL,
    trace_version TEXT NOT NULL,
    route TEXT,
    base_decision TEXT,
    final_decision TEXT,
    audit_status TEXT,
    failure_category TEXT,
    failure_retriable INTEGER NOT NULL,
    planned_destination TEXT,
    actual_destination TEXT,
    attempted INTEGER NOT NULL,
    committed INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,
    successful_calls INTEGER NOT NULL,
    cost_cny REAL,
    cost_cny_known INTEGER NOT NULL,
    raw_trace TEXT NOT NULL,
    UNIQUE(protocol_version, dataset, case_id, repetition, arm)
);
CREATE INDEX IF NOT EXISTS idx_audit_runs_decision ON audit_runs(final_decision);
CREATE INDEX IF NOT EXISTS idx_audit_runs_case ON audit_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_runs_failure ON audit_runs(failure_category);
CREATE VIEW IF NOT EXISTS v_decision_by_arm AS select arm, final_decision, count(*) as n from audit_runs group by arm, final_decision;
CREATE VIEW IF NOT EXISTS v_failure_by_category AS select failure_category, failure_retriable, count(*) as n from audit_runs group by failure_category, failure_retriable;
CREATE VIEW IF NOT EXISTS v_cost_by_arm AS select arm, count(*) as runs, sum(total_tokens) as tokens, sum(successful_calls) as calls, sum(cost_cny) as cost_cny from audit_runs group by arm;
"""


def _bool(value: Any) -> int:
    return int(bool(value))


def flatten_record(record: dict[str, Any]) -> tuple[Any, ...]:
    trace = record["audit_trace"]
    decision = trace["decision"]
    failure = trace["failure"]
    execution = trace["execution"]
    operations = trace["operations"]
    return (
        record["protocol_version"], record["dataset"], _bool(record["evaluation_valid"]),
        record["case_id"], record.get("repetition"), record["arm"],
        _bool(record["response_usable"]), trace["trace_version"], trace.get("route"),
        decision.get("base"), decision.get("final"), decision.get("audit_status"),
        failure.get("category"), _bool(failure.get("retriable")),
        execution.get("planned_destination"), execution.get("actual_destination"),
        _bool(execution.get("attempted")), _bool(execution.get("committed")),
        operations.get("total_tokens", 0), operations.get("successful_calls", 0),
        operations.get("cost_cny"), _bool(operations.get("cost_cny_known")),
        json.dumps(trace, ensure_ascii=False, sort_keys=True),
    )


def init_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA)
    return connection


def import_jsonl(jsonl_path: Path, db_path: Path) -> int:
    records = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    connection = init_db(db_path)
    before_count = connection.execute(
        "SELECT COUNT(*) FROM audit_runs"
    ).fetchone()[0]
    with connection:
        connection.executemany(
            """INSERT OR REPLACE INTO audit_runs (
                protocol_version, dataset, evaluation_valid, case_id, repetition,
                arm, response_usable, trace_version, route, base_decision,
                final_decision, audit_status, failure_category, failure_retriable,
                planned_destination, actual_destination, attempted, committed,
                total_tokens, successful_calls, cost_cny, cost_cny_known, raw_trace
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (flatten_record(record) for record in records),
        )
    after_count = connection.execute(
        "SELECT COUNT(*) FROM audit_runs"
    ).fetchone()[0]
    count = after_count - before_count
    overwritten_count = len(records) - count
    if overwritten_count > 0:
        message = f"覆盖了 {overwritten_count} 条重复记录"
        warnings.warn(message, UserWarning, stacklevel=2)
        print(message)
    connection.close()
    return count


def export_csv(db_path: Path, csv_path: Path) -> int:
    connection = sqlite3.connect(db_path)
    cursor = connection.execute("SELECT * FROM audit_runs ORDER BY id")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8-sig") as output:
        writer = csv.writer(output)
        writer.writerow([column[0] for column in cursor.description])
        rows = cursor.fetchall()
        writer.writerows(rows)
    connection.close()
    return len(rows)


def export_report(db_path: Path, output_directory: Path) -> dict[str, int]:
    views = {
        "v_decision_by_arm": "view_decision_by_arm.csv",
        "v_failure_by_category": "view_failure_by_category.csv",
        "v_cost_by_arm": "view_cost_by_arm.csv",
    }
    connection = sqlite3.connect(db_path)
    output_directory.mkdir(parents=True, exist_ok=True)
    exported: dict[str, int] = {}
    try:
        for view_name, filename in views.items():
            cursor = connection.execute(f"SELECT * FROM {view_name}")
            rows = cursor.fetchall()
            with (output_directory / filename).open(
                "w", newline="", encoding="utf-8"
            ) as output:
                writer = csv.writer(output)
                writer.writerow([column[0] for column in cursor.description])
                writer.writerows(rows)
            exported[view_name] = len(rows)
    finally:
        connection.close()
    return exported


def _grouped_bar_svg(
    *,
    groups: tuple[str, ...],
    series: tuple[str, ...],
    values: dict[tuple[str, str], int | float],
    colors: dict[str, str],
    legend_labels: dict[str, str],
    title: str,
    description: str,
    title_id: str,
    series_labels: dict[str, str] | None = None,
    group_colors: dict[str, str] | None = None,
    value_labels: dict[tuple[str, str], str] | None = None,
    width: int = 760,
    height: int = 500,
    show_legend: bool = True,
) -> str:
    series_labels = series_labels or {name: name for name in series}
    value_labels = value_labels or {}
    margin_left, margin_right = 80, 40
    margin_top, margin_bottom = 90, 100
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    baseline = margin_top + plot_height
    max_count = max(values.values(), default=0)
    if max_count <= 0:
        y_max = 1
        tick_count = 1
    elif max_count < 1:
        scale = 10 ** math.floor(math.log10(max_count))
        y_max = math.ceil(max_count / scale) * scale
        tick_count = 5
    else:
        y_max = max_count
        tick_count = max(1, min(5, int(y_max)))
    bar_width, bar_gap = 54, 12
    group_width = len(series) * bar_width + (len(series) - 1) * bar_gap
    group_slot = plot_width / len(groups)

    svg: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-labelledby="{escape(title_id)} {escape(title_id)}-description">',
        f'<title id="{escape(title_id)}">{escape(title)}</title>',
        f'<desc id="{escape(title_id)}-description">{escape(description)}</desc>',
        f'<text x="{width / 2:.1f}" y="36" text-anchor="middle" '
        f'class="chart-title">{escape(title)}</text>',
    ]

    for index in range(tick_count + 1):
        value = y_max * index / tick_count
        y = baseline - value / y_max * plot_height
        svg.append(
            f'<line x1="{margin_left}" y1="{y:.1f}" x2="{width - margin_right}" '
            f'y2="{y:.1f}" class="grid-line" />'
        )
        svg.append(
            f'<text x="{margin_left - 10}" y="{y + 5:.1f}" text-anchor="end" '
            f'class="axis-label">{value:g}</text>'
        )

    svg.extend(
        [
            f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" '
            f'y2="{baseline}" class="axis-line" />',
            f'<line x1="{margin_left}" y1="{baseline}" x2="{width - margin_right}" '
            f'y2="{baseline}" class="axis-line" />',
        ]
    )

    for group_index, group in enumerate(groups):
        group_start = (
            margin_left
            + group_index * group_slot
            + (group_slot - group_width) / 2
        )
        group_center = group_start + group_width / 2
        svg.append(
            f'<text x="{group_center:.1f}" y="{baseline + 38}" text-anchor="middle" '
            f'class="axis-label">{escape(group)}</text>'
        )
        for series_index, series_name in enumerate(series):
            value = values[(group, series_name)]
            bar_height = value / y_max * plot_height
            x = group_start + series_index * (bar_width + bar_gap)
            y = baseline - bar_height
            display_value = value_labels.get((group, series_name), str(value))
            label = f"{group}-{series_labels[series_name]}={display_value}"
            fill = (group_colors or {}).get(group, colors[series_name])
            svg.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width}" '
                f'height="{bar_height:.1f}" fill="{fill}" '
                f'aria-label="{escape(label)}"><title>{escape(label)}</title></rect>'
            )
            svg.append(
                f'<text x="{x + bar_width / 2:.1f}" '
                f'y="{max(margin_top + 16, y - 8):.1f}" text-anchor="middle" '
                f'class="value-label">{escape(display_value)}</text>'
            )

    if show_legend:
        legend_y = height - 32
        legend_x = margin_left
        for series_name in series:
            svg.append(
                f'<rect x="{legend_x}" y="{legend_y - 13}" width="16" height="16" '
                f'fill="{colors[series_name]}" />'
            )
            svg.append(
                f'<text x="{legend_x + 24}" y="{legend_y}" class="legend-label">'
                f'{escape(legend_labels[series_name])}</text>'
            )
            legend_x += 120
    svg.append("</svg>")
    return "\n".join(svg)


def export_dashboard(db_path: Path, html_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        decision_rows = connection.execute(
            "SELECT arm, final_decision, n FROM v_decision_by_arm"
        ).fetchall()
        failure_rows = connection.execute(
            "SELECT failure_category, failure_retriable, n "
            "FROM v_failure_by_category"
        ).fetchall()
        cost_rows = connection.execute(
            "SELECT arm, runs, tokens, calls, cost_cny FROM v_cost_by_arm"
        ).fetchall()
    finally:
        connection.close()

    arms = ("multi", "single")
    decisions = ("permit", "hold", "deny")
    decision_colors = {
        "permit": "#4caf50",
        "hold": "#ff9800",
        "deny": "#f44336",
    }
    decision_counts = {
        (arm, decision): 0 for arm in arms for decision in decisions
    }
    for arm, decision, n in decision_rows:
        if arm in arms and decision in decisions:
            decision_counts[(arm, decision)] = int(n or 0)

    failure_categories = ("infrastructure", "model_contract", "none")
    failure_series = ("retriable", "non-retriable")
    failure_colors = {
        "retriable": "#2196f3",
        "non-retriable": "#9e9e9e",
    }
    failure_counts = {
        (category, retriable): 0
        for category in failure_categories
        for retriable in failure_series
    }
    for category, failure_retriable, n in failure_rows:
        retriable = "retriable" if int(failure_retriable or 0) else "non-retriable"
        if category in failure_categories:
            failure_counts[(category, retriable)] = int(n or 0)

    cost_metrics = ("runs", "tokens", "calls", "cost_cny")
    cost_rows_by_arm = {
        arm: {
            "runs": runs,
            "tokens": tokens,
            "calls": calls,
            "cost_cny": cost_cny,
        }
        for arm, runs, tokens, calls, cost_cny in cost_rows
        if arm in arms
    }
    cost_colors = {"multi": "#673ab7", "single": "#009688"}
    cost_svgs: list[str] = []
    for metric in cost_metrics:
        metric_values: dict[tuple[str, str], int | float] = {}
        metric_labels: dict[tuple[str, str], str] = {}
        for arm in arms:
            raw_value = cost_rows_by_arm.get(arm, {}).get(metric)
            if metric == "cost_cny":
                value: int | float = float(raw_value or 0)
                display_value = str(raw_value if raw_value is not None else 0)
            else:
                value = int(raw_value or 0)
                display_value = str(value)
            metric_values[(arm, "value")] = value
            metric_labels[(arm, "value")] = display_value
        cost_svgs.append(
            _grouped_bar_svg(
                groups=arms,
                series=("value",),
                values=metric_values,
                colors={"value": "#673ab7"},
                group_colors=cost_colors,
                legend_labels={"value": metric},
                title={
                    "runs": "运行次数",
                    "tokens": "Token 总数",
                    "calls": "调用次数",
                    "cost_cny": "成本（元）",
                }[metric],
                description=f"按 arm 比较 {metric}",
                title_id=f"cost-{metric}-chart-title",
                series_labels={"value": metric},
                value_labels=metric_labels,
                width=760,
                height=500,
                show_legend=False,
            )
        )

    decision_svg = _grouped_bar_svg(
        groups=arms,
        series=decisions,
        values=decision_counts,
        colors=decision_colors,
        legend_labels={decision: decision for decision in decisions},
        title="按 arm 的 permit / hold / deny 分布",
        description="按 arm 分组显示 permit、hold、deny 的记录数量",
        title_id="decision-chart-title",
    )
    failure_svg = _grouped_bar_svg(
        groups=failure_categories,
        series=failure_series,
        values=failure_counts,
        colors=failure_colors,
        legend_labels={
            "retriable": "可重试",
            "non-retriable": "不可重试",
        },
        title="按失败分类的可重试/不可重试分布",
        description="按 failure_category 分组显示可重试与不可重试的记录数量",
        title_id="failure-chart-title",
    )

    html = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>审计决策分布</title>
<style>
  body { margin: 2rem; color: #222; font-family: sans-serif; }
  h1 { font-size: 1.5rem; font-weight: 600; }
  .chart-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
  .chart-grid svg { display: block; width: 100%; height: auto; margin-bottom: 0; border: 1px solid #ddd; background: #fff; }
  @media (max-width: 800px) { .chart-grid { grid-template-columns: 1fr; } }
  .cost-legend { margin: 0 0 1rem; }
  .cost-legend span { margin-right: 1.5rem; }
  .cost-legend i { display: inline-block; width: 0.8rem; height: 0.8rem; margin-right: 0.35rem; }
  .chart-title { font-size: 18px; font-weight: 600; }
  .axis-label, .legend-label { font-size: 14px; }
  .value-label { font-size: 14px; font-weight: 600; }
  .axis-line { stroke: #444; stroke-width: 1; }
  .grid-line { stroke: #ddd; stroke-width: 1; }
</style>
</head>
<body>
<h1>审计决策分布</h1>
<div class="chart-grid">""" + decision_svg + "\n" + failure_svg + """</div>
<h2>成本与 token</h2>
<div class="cost-legend"><span><i style="background:#673ab7"></i>multi</span><span><i style="background:#009688"></i>single</span></div>
<div class="chart-grid">""" + "\n".join(cost_svgs) + """</div>
</body>
</html>
"""
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import v0.4 audit JSONL into SQLite or CSV")
    subparsers = parser.add_subparsers(dest="command", required=True)
    import_parser = subparsers.add_parser("import")
    import_parser.add_argument("jsonl", type=Path)
    import_parser.add_argument("db", type=Path)
    csv_parser = subparsers.add_parser("csv")
    csv_parser.add_argument("db", type=Path)
    csv_parser.add_argument("output", type=Path)
    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("db", type=Path)
    report_parser.add_argument("output_directory", type=Path)
    dashboard_parser = subparsers.add_parser("dashboard")
    dashboard_parser.add_argument("db", type=Path)
    dashboard_parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "import":
        count = import_jsonl(args.jsonl, args.db)
        print(f"Processed {count} audit rows")
    elif args.command == "csv":
        count = export_csv(args.db, args.output)
        print(f"Processed {count} audit rows")
    elif args.command == "report":
        counts = export_report(args.db, args.output_directory)
        print(f"Processed {sum(counts.values())} report rows")
    elif args.command == "dashboard":
        export_dashboard(args.db, args.output)
        print(f"Wrote dashboard to {args.output}")


if __name__ == "__main__":
    main()
