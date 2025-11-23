"""
Script to view top 3 CWE types and names
"""

import sys
from pathlib import Path
from dotenv import load_dotenv
import logging
from vulnerability_pattern_miner import DatabaseConnector
import pandas as pd
from sqlalchemy import text

# Load environment variables
load_dotenv(".env")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def check_top_cwe(
    top_n: int = 3, min_score: int = 65, programming_languages: list = None
):
    """
    View top n CWE types and names

    Args:
        top_n: Return top n most common CWE, default 3
        min_score: Minimum value of fixes.score, default 65
        programming_languages: List of programming languages, default ['Java']
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info("=" * 60)
    logger.info(f"Viewing top {top_n} CWE types and names")
    logger.info(f"Configuration: min_score={min_score}, languages={programming_languages}")
    logger.info("=" * 60)

    # Initialize database connection
    db_connector = DatabaseConnector()

    # Build language filter conditions
    lang_conditions = []
    params = {"min_score": min_score, "top_n": top_n}
    for i, lang in enumerate(programming_languages):
        lang_conditions.append(f"LOWER(fc.programming_language) = LOWER(:lang_{i})")
        params[f"lang_{i}"] = lang

    lang_filter = " OR ".join(lang_conditions)

    # Optimized SQL: Complete CWE statistics directly in database to avoid transferring large amounts of data
    logger.info("\nExecuting optimized SQL query...")
    query = f"""
    WITH good_fixes AS (
      SELECT DISTINCT f.cve_id, f.hash, f.repo_url
      FROM fixes f
      WHERE f.score >= :min_score
    ),
    single_file_fixes AS (
      SELECT 
        gf.cve_id,
        gf.hash,
        gf.repo_url
      FROM good_fixes gf
      JOIN file_change fc ON fc.hash = gf.hash
      JOIN commits c ON c.hash = gf.hash AND c.repo_url = gf.repo_url
      WHERE COALESCE(c.merge, FALSE) = FALSE
        AND COALESCE(fc.diff, '') <> ''
        AND fc.code_before IS NOT NULL 
        AND fc.code_before <> 'None'
        AND ({lang_filter})
      GROUP BY gf.cve_id, gf.hash, gf.repo_url
      HAVING COUNT(fc.file_change_id) = 1
    ),
    cwe_stats AS (
      SELECT 
        cc.cwe_id,
        c.cwe_name,
        COUNT(DISTINCT sff.cve_id) as fix_count,
        array_agg(DISTINCT sff.cve_id ORDER BY sff.cve_id) FILTER (WHERE sff.cve_id IS NOT NULL) as cve_list
      FROM single_file_fixes sff
      JOIN cwe_classification cc ON cc.cve_id = sff.cve_id
      JOIN cwe c ON c.cwe_id = cc.cwe_id
      GROUP BY cc.cwe_id, c.cwe_name
      HAVING COUNT(DISTINCT sff.cve_id) > 1
    )
    SELECT 
      cwe_id,
      cwe_name,
      fix_count,
      cve_list
    FROM cwe_stats
    ORDER BY fix_count DESC
    LIMIT :top_n;
    """

    try:
        top_cwe_df = db_connector.execute_query(query, params=params)
    except Exception as e:
        # If array_agg is not supported, use simplified version
        logger.warning(f"Failed to use array_agg, trying simplified query: {e}")
        query_simple = f"""
        WITH good_fixes AS (
          SELECT DISTINCT f.cve_id, f.hash, f.repo_url
          FROM fixes f
          WHERE f.score >= :min_score
        ),
        single_file_fixes AS (
          SELECT 
            gf.cve_id,
            gf.hash,
            gf.repo_url
          FROM good_fixes gf
          JOIN file_change fc ON fc.hash = gf.hash
          JOIN commits c ON c.hash = gf.hash AND c.repo_url = gf.repo_url
          WHERE COALESCE(c.merge, FALSE) = FALSE
            AND COALESCE(fc.diff, '') <> ''
            AND fc.code_before IS NOT NULL 
            AND fc.code_before <> 'None'
            AND ({lang_filter})
          GROUP BY gf.cve_id, gf.hash, gf.repo_url
          HAVING COUNT(fc.file_change_id) = 1
        ),
        cwe_stats AS (
          SELECT 
            cc.cwe_id,
            c.cwe_name,
            COUNT(DISTINCT sff.cve_id) as fix_count
          FROM single_file_fixes sff
          JOIN cwe_classification cc ON cc.cve_id = sff.cve_id
          JOIN cwe c ON c.cwe_id = cc.cwe_id
          GROUP BY cc.cwe_id, c.cwe_name
          HAVING COUNT(DISTINCT sff.cve_id) > 1
        )
        SELECT 
          cwe_id,
          cwe_name,
          fix_count
        FROM cwe_stats
        ORDER BY fix_count DESC
        LIMIT :top_n;
        """
        top_cwe_df = db_connector.execute_query(query_simple, params=params)

        # If cve_list column doesn't exist, need to query separately
        if "cve_list" not in top_cwe_df.columns:
            logger.info("Getting CVE examples for each CWE...")
            for idx, row in top_cwe_df.iterrows():
                cve_query = f"""
                SELECT DISTINCT sff.cve_id
                FROM (
                  SELECT DISTINCT f.cve_id, f.hash, f.repo_url
                  FROM fixes f
                  WHERE f.score >= :min_score
                ) gf
                JOIN file_change fc ON fc.hash = gf.hash
                JOIN commits c ON c.hash = gf.hash AND c.repo_url = gf.repo_url
                JOIN cwe_classification cc ON cc.cve_id = gf.cve_id
                WHERE cc.cwe_id = :cwe_id
                  AND COALESCE(c.merge, FALSE) = FALSE
                  AND COALESCE(fc.diff, '') <> ''
                  AND fc.code_before IS NOT NULL 
                  AND fc.code_before <> 'None'
                  AND ({lang_filter})
                GROUP BY gf.cve_id, gf.hash, gf.repo_url
                HAVING COUNT(fc.file_change_id) = 1
                LIMIT 5
                """
                cve_params = params.copy()
                cve_params["cwe_id"] = row["cwe_id"]
                cve_df = db_connector.execute_query(cve_query, params=cve_params)
                top_cwe_df.at[idx, "cve_list"] = (
                    cve_df["cve_id"].tolist() if not cve_df.empty else []
                )

    if top_cwe_df.empty:
        logger.warning("No matching CWE found")
        return

    logger.info(f"Query completed, found {len(top_cwe_df)} top CWE")

    # Process cve_list column, convert to string format for easier saving
    if "cve_list" in top_cwe_df.columns:

        def format_cve_list(cve_list):
            try:
                # Handle None
                if cve_list is None:
                    return ""

                # Handle list type
                if isinstance(cve_list, list):
                    return ", ".join(str(c) for c in cve_list[:10])  # Show at most 10

                # Handle numpy arrays or other array types
                if hasattr(cve_list, "__iter__") and not isinstance(cve_list, str):
                    try:
                        cve_list = list(cve_list)
                        return ", ".join(str(c) for c in cve_list[:10])
                    except (TypeError, ValueError):
                        pass

                # Try to check if it's NaN (avoid ambiguity errors with array types)
                try:
                    if pd.isna(cve_list):
                        return ""
                except (ValueError, TypeError):
                    pass  # If it's an array type, pd.isna may fail, continue processing

                # PostgreSQL array format (string form)
                cve_str = str(cve_list)
                if cve_str.startswith("{") and cve_str.endswith("}"):
                    cve_str = cve_str[1:-1]  # Remove curly braces
                cves = [c.strip() for c in cve_str.split(",") if c.strip()]
                return ", ".join(cves[:10])
            except Exception as e:
                # If all methods fail, return string representation
                return str(cve_list)[:100]  # Limit length

        top_cwe_df["cve_examples"] = top_cwe_df["cve_list"].apply(format_cve_list)
        # Remove original cve_list column (may be array type, not convenient to save)
        top_cwe_df = top_cwe_df.drop(columns=["cve_list"])

    # Display results
    logger.info("\n" + "=" * 60)
    logger.info(f"Top {len(top_cwe_df)} CWE types and names:")
    logger.info("=" * 60)

    for idx, (_, row) in enumerate(top_cwe_df.iterrows(), 1):
        logger.info(f"\n#{idx} {row['cwe_id']}: {row['cwe_name']}")
        logger.info(f"   Occurrence count: {row['fix_count']} CVEs")

        if "cve_examples" in row and row["cve_examples"]:
            logger.info(f"   Example CVEs: {row['cve_examples']}")
        else:
            logger.info(f"   Example CVEs: (not retrieved)")

    # Save results to CSV file
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"top_{top_n}_cwe.csv"

    # Rearrange column order for better readability
    columns_order = ["cwe_id", "cwe_name", "fix_count"]
    if "cve_examples" in top_cwe_df.columns:
        columns_order.append("cve_examples")
    # Add other columns that may exist
    for col in top_cwe_df.columns:
        if col not in columns_order:
            columns_order.append(col)

    top_cwe_df_output = top_cwe_df[
        [col for col in columns_order if col in top_cwe_df.columns]
    ]
    top_cwe_df_output.to_csv(output_file, index=False, encoding="utf-8")

    logger.info("\n" + "=" * 60)
    logger.info(f"Results saved to: {output_file}")
    logger.info("Completed!")

    return top_cwe_df


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="View top CWE types and names")
    parser.add_argument(
        "--top-n",
        type=int,
        default=3,
        help="Return top n most common CWE (default: 3)",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=65,
        help="Minimum value of fixes.score (default: 65)",
    )
    parser.add_argument(
        "--languages",
        nargs="+",
        default=["java"],
        help="List of programming languages, case-insensitive (default: java)",
    )

    args = parser.parse_args()

    check_top_cwe(
        top_n=args.top_n,
        min_score=args.min_score,
        programming_languages=args.languages,
    )
