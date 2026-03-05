#!/usr/bin/env python3

import sys
import json
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path


def generate_report(file_path: str) -> dict:
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    total_lines = 0
    parsed_objects = []
    key_counter = Counter()
    value_counter = defaultdict(Counter)

    with file_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            total_lines += 1

            try:
                json_obj = json.loads(line)
                parsed_objects.append(json_obj)

                for key, value in json_obj.items():
                    key_counter[key] += 1
                  
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, sort_keys=True)

                    value_counter[key][value] += 1

            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON on line {line_number}: {e}")

    report = {
        "file_path": str(file_path.resolve()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_lines_read": total_lines,magpie_log_report.
        "total_valid_json_objects": len(parsed_objects),
        "key_counts": dict(key_counter),
        "value_counts_by_key": {
            key: dict(counter) for key, counter in value_counter.items()
        },
    }

    return report


def main():
    if len(sys.argv) != 2:
        print("Usage: python event_report.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]

    report = generate_report(input_file)

    print(json.dumps(report, indent=4))


if __name__ == "__main__":
    main()
