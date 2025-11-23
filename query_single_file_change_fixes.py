"""
Query Fixes for Single File Change

Query records that meet the following conditions:
1. fixes.score >= 65
2. Exclude merge commits
3. Non-empty diff
4. Specified programming language (e.g., Java)
5. Each fix (commit) has only one file_change

Usage:
    python query_single_file_change_fixes.py --languages java --min-score 65
"""

import os
import sys
from pathlib import Path
from typing import Optional, List
import logging
import argparse
from dotenv import load_dotenv
import pandas as pd
import sqlalchemy
from sqlalchemy import text

# Load environment variables
load_dotenv(".env")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("query_single_file_change_fixes.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class DatabaseConnector:
    """Database connector"""

    def __init__(self):
        self.engine = None
        self._connect()

    def _connect(self):
        """Connect to the database"""
        try:
            db_url = (
                f'postgresql://{os.getenv("POSTGRES_USER")}:'
                f'{os.getenv("POSTGRES_PASSWORD")}@'
                f'{os.getenv("DB_HOST")}:{os.getenv("POSTGRES_PORT")}/'
                f'{os.getenv("POSTGRES_DB")}'
            )
            self.engine = sqlalchemy.create_engine(db_url)
            logger.info("Database connected successfully")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            sys.exit(1)

    def execute_query(self, query: str, params: Optional[dict] = None) -> pd.DataFrame:
        """Execute query and return DataFrame"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text(query), params or {})
                return pd.DataFrame(result.fetchall(), columns=result.keys())
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise


def query_single_file_change_fixes(
    db_connector: DatabaseConnector,
    min_score: int = 65,
    exclude_merge_commits: bool = True,
    programming_languages: list = None,
    require_diff: bool = True,
) -> pd.DataFrame:
    """
    Query records where each fix has only one file_change

    Args:
        db_connector: Database connector
        min_score: Minimum value of fixes.score, default 65
        exclude_merge_commits: Whether to exclude merge commits, default True
        programming_languages: List of programming languages, default ['Java']
        require_diff: Whether to require non-empty diff, default True

    Returns:
        DataFrame containing vulnerable code information
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info(f"Starting to query fixes for single file_change in {programming_languages}...")
    logger.info(
        f"Filter conditions: min_score={min_score}, exclude_merge={exclude_merge_commits}, "
        f"require_diff={require_diff}, single_file_change_only=True"
    )

    # Build language filter conditions (case-insensitive matching)
    lang_conditions = []
    for i, lang in enumerate(programming_languages):
        lang_conditions.append(f"LOWER(fc.programming_language) = LOWER(:lang_{i})")

    # Prepare parameters
    params = {"min_score": min_score}
    for i, lang in enumerate(programming_languages):
        params[f"lang_{i}"] = lang

    lang_filter = " OR ".join(lang_conditions)

    # Build WHERE conditions
    where_conditions = []

    # diff condition
    if require_diff:
        where_conditions.append("COALESCE(fc.diff, '') <> ''")

    # merge commit condition
    if exclude_merge_commits:
        where_conditions.append("COALESCE(c.merge, FALSE) = FALSE")

    # code_before condition: filter out 'None' strings and NULL values
    where_conditions.append("fc.code_before IS NOT NULL AND fc.code_before <> 'None'")

    # Programming language condition (case-insensitive)
    where_conditions.append(f"({lang_filter})")

    where_clause = " AND ".join(where_conditions)

    query = f"""
    -- Query records where each fix has only one file_change
    WITH good_fixes AS (
      SELECT f.cve_id, f.hash, f.repo_url, f.score
      FROM fixes f
      WHERE f.score >= :min_score
    ),
    -- Count file_change numbers for each fix, only keep those with count = 1
    single_file_change_fixes AS (
      SELECT 
        gf.hash,
        gf.repo_url
      FROM good_fixes gf
      JOIN file_change fc
        ON fc.hash = gf.hash
      GROUP BY gf.hash, gf.repo_url
      HAVING COUNT(fc.file_change_id) = 1
    )
    SELECT
      gf.cve_id,
      gf.repo_url,
      gf.hash,
      gf.score,
      c.author_date,
      c.msg,
      fc.file_change_id,
      fc.filename,
      fc.programming_language,
      fc.code_before,
      fc.code_after,
      fc.diff
    FROM good_fixes gf
    JOIN single_file_change_fixes sfcf
      ON sfcf.hash = gf.hash AND sfcf.repo_url = gf.repo_url
    JOIN commits c
      ON c.hash = gf.hash AND c.repo_url = gf.repo_url
    JOIN file_change fc
      ON fc.hash = gf.hash
    WHERE {where_clause};
    """

    df = db_connector.execute_query(query, params=params)

    logger.info(f"Query results: {len(df)} records")
    logger.info(f"Involving {df['cve_id'].nunique()} CVEs")
    logger.info(f"Involving {df['hash'].nunique()} commits")
    logger.info(f"Involving {df['repo_url'].nunique()} repositories")
    logger.info(f"Involving {df['filename'].nunique()} files")

    return df


def main(
    min_score: int = 65,
    exclude_merge_commits: bool = True,
    programming_languages: List[str] = None,
    require_diff: bool = True,
    output_file: str = None,
):
    """
    Main function: Query fixes for single file_change

    Args:
        min_score: Minimum value of fixes.score, default 65
        exclude_merge_commits: Whether to exclude merge commits, default True
        programming_languages: List of programming languages, default ['Java']
        require_diff: Whether to require non-empty diff, default True
        output_file: Output file path, default None (auto-generated)
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info("=" * 60)
    logger.info("Query Fixes for Single File Change")
    logger.info(f"Configuration: min_score={min_score}, exclude_merge={exclude_merge_commits}")
    logger.info(f"Languages: {programming_languages}")
    logger.info("=" * 60)

    # Initialize database connection
    db_connector = DatabaseConnector()

    # Execute query
    result_df = query_single_file_change_fixes(
        db_connector,
        min_score=min_score,
        exclude_merge_commits=exclude_merge_commits,
        programming_languages=programming_languages,
        require_diff=require_diff,
    )

    # Save results
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    if output_file is None:
        lang_str = "_".join(programming_languages).lower()
        output_file = output_dir / f"single_file_change_fixes_{lang_str}_score{min_score}.csv"

    # Exclude code_before and code_after columns (if file is large)
    columns_to_save = [
        col
        for col in result_df.columns
        if col not in ["code_before", "code_after"]
    ]
    output_df = result_df[columns_to_save].copy()

    output_df.to_csv(output_file, index=False, encoding="utf-8")
    logger.info(f"Results saved to: {output_file}")

    # Print statistics
    logger.info("\n" + "=" * 60)
    logger.info("Statistics:")
    logger.info(f"  Total records: {len(result_df)}")
    logger.info(f"  Unique CVE count: {result_df['cve_id'].nunique()}")
    logger.info(f"  Unique commit count: {result_df['hash'].nunique()}")
    logger.info(f"  Unique repository count: {result_df['repo_url'].nunique()}")
    logger.info(f"  Unique file count: {result_df['filename'].nunique()}")
    logger.info("=" * 60)

    logger.info("\nQuery completed!")


def parse_arguments():
    """
    Parse command line arguments

    Returns:
        argparse.Namespace: Parsed command line arguments object
    """
    parser = argparse.ArgumentParser(description="Query Fixes for Single File Change")
    parser.add_argument(
        "--min-score",
        type=int,
        default=65,
        help="Minimum value of fixes.score (default: 65)",
    )
    parser.add_argument(
        "--include-merge",
        action="store_true",
        help="Include merge commits (default: excluded)",
    )
    parser.add_argument(
        "--languages",
        nargs="+",
        default=["java"],
        help="List of programming languages, case-insensitive (default: java). Example: --languages java or --languages Java Go",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: output/single_file_change_fixes_{language}_score{score}.csv)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    main(
        min_score=args.min_score,
        exclude_merge_commits=not args.include_merge,
        programming_languages=args.languages,
        require_diff=True,
        output_file=args.output,
    )

