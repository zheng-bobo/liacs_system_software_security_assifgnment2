"""
Query a sample record from method_change table
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import pandas as pd
import sqlalchemy
from sqlalchemy import text

# Load environment variables
load_dotenv(".env")

# Database connection
db_url = (
    f'postgresql://{os.getenv("POSTGRES_USER")}:'
    f'{os.getenv("POSTGRES_PASSWORD")}@'
    f'{os.getenv("DB_HOST")}:{os.getenv("POSTGRES_PORT")}/'
    f'{os.getenv("POSTGRES_DB")}'
)

engine = sqlalchemy.create_engine(db_url)

# Query one method_change record, including associated file_change information
query = """
SELECT 
    mc.method_change_id,
    mc.file_change_id,
    mc.name as method_name,
    mc.signature,
    mc.parameters,
    mc.start_line,
    mc.end_line,
    mc.code,
    mc.before_change,
    mc.nloc,
    mc.complexity,
    mc.token_count,
    mc.top_nesting_level,
    fc.code_before as file_code_before,
    fc.code_after as file_code_after,
    LENGTH(fc.code_before) as file_code_before_length,
    LENGTH(fc.code_after) as file_code_after_length
FROM method_change mc
JOIN file_change fc ON mc.file_change_id = fc.file_change_id
WHERE fc.code_before IS NOT NULL
  AND fc.code_before <> ''
  AND mc.start_line IS NOT NULL
  AND mc.end_line IS NOT NULL
LIMIT 1;
"""

print("Querying a sample record from method_change table...")
print("=" * 80)

with engine.connect() as conn:
    result = conn.execute(text(query))
    rows = result.fetchall()
    df = pd.DataFrame(rows, columns=result.keys())

    if df.empty:
        print("No data found")
    else:
        print(f"\nFound 1 record\n")

        row = df.iloc[0]

        print("=" * 80)
        print("Basic Information:")
        print("=" * 80)
        print(f"method_change_id: {row['method_change_id']}")
        print(f"file_change_id: {row['file_change_id']}")
        print(f"method_name: {row['method_name']}")
        print(f"signature: {row['signature']}")
        print(f"parameters: {row['parameters']}")
        print(f"start_line: {row['start_line']} (type: {type(row['start_line'])})")
        print(f"end_line: {row['end_line']} (type: {type(row['end_line'])})")
        print(
            f"before_change: {row['before_change']} (type: {type(row['before_change'])})"
        )
        print(f"nloc: {row['nloc']}")
        print(f"complexity: {row['complexity']}")
        print(f"token_count: {row['token_count']}")
        print(f"top_nesting_level: {row['top_nesting_level']}")

        print("\n" + "=" * 80)
        print("File Code Information:")
        print("=" * 80)
        print(f"file_code_before length: {row['file_code_before_length']}")
        print(f"file_code_after length: {row['file_code_after_length']}")

        print("\n" + "=" * 80)
        print("method_change.code field (method code after change):")
        print("=" * 80)
        code = row["code"]
        if code:
            print(f"Length: {len(str(code))}")
            print(f"First 500 characters:")
            print("-" * 80)
            print(str(code)[:500])
            print("-" * 80)
        else:
            print("(empty)")

        print("\n" + "=" * 80)
        print("method_change.before_change field:")
        print("=" * 80)
        before_change = row["before_change"]
        print(f"Value: {before_change}")
        print(f"Type: {type(before_change)}")
        print(f"Length: {len(str(before_change)) if before_change else 0}")

        print("\n" + "=" * 80)
        print(
            "Method code extracted from file_code_before (based on start_line and end_line):"
        )
        print("=" * 80)
        file_code_before = row["file_code_before"]
        start_line = int(row["start_line"]) if row["start_line"] else None
        end_line = int(row["end_line"]) if row["end_line"] else None

        if file_code_before and start_line and end_line:
            lines = file_code_before.split("\n")
            start_idx = max(0, start_line - 1)
            end_idx = min(len(lines), end_line)

            print(f"Total file lines: {len(lines)}")
            print(f"start_line: {start_line} -> start_idx: {start_idx}")
            print(f"end_line: {end_line} -> end_idx: {end_idx}")

            if start_idx < end_idx and start_idx < len(lines):
                extracted_code = "\n".join(lines[start_idx:end_idx])
                print(f"Extracted code length: {len(extracted_code)}")
                print("-" * 80)
                print(
                    extracted_code[:500]
                    if len(extracted_code) > 500
                    else extracted_code
                )
                print("-" * 80)
            else:
                print(
                    f"Warning: Invalid line number range (start_idx={start_idx}, end_idx={end_idx}, len(lines)={len(lines)})"
                )
        else:
            print("Unable to extract: file_code_before or line numbers are empty")
