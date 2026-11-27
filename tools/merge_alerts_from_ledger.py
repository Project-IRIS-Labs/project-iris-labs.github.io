#!/usr/bin/env python3
import argparse
import json
import sqlite3
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    args = parser.parse_args()

    connection = sqlite3.connect(args.ledger)
    rows = connection.execute(
        "SELECT document_id, alert_json FROM investigations ORDER BY event_time, alert_id"
    ).fetchall()
    connection.close()

    groups = []
    by_document = {}
    for document_id, alert_json in rows:
        if document_id not in by_document:
            by_document[document_id] = []
            groups.append(by_document[document_id])
        by_document[document_id].append(json.loads(alert_json))

    data = json.loads(args.data.read_text(encoding="utf-8"))
    incidents = data["incidents"]
    if len(groups) != len(incidents):
        raise SystemExit(f"사건 그룹 불일치: ledger={len(groups)} data={len(incidents)}")

    for incident, alerts in zip(incidents, groups):
        if incident["alert_count"] != len(alerts):
            raise SystemExit(f"Alert 수 불일치: {incident['id']}")
        incident["raw_alerts"] = alerts

    args.data.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
