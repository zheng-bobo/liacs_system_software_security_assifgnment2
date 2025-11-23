"""
GitHub Query Generation Module

Generate GitHub search query keywords based on vulnerability patterns and call GitHub API for searching.
"""

import os
import time
import logging
from typing import Dict, List, Optional
from pathlib import Path
import pandas as pd
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv(".env")

logger = logging.getLogger(__name__)


class GitHubQueryGenerator:
    """GitHub Query Generator Class"""

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize GitHub Query Generator

        Args:
            github_token: GitHub Personal Access Token, if None then read from environment variable GITHUB_TOKEN
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.api_base_url = "https://api.github.com"
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def _make_github_request(
        self, endpoint: str, params: Optional[Dict] = None, max_retries: int = 3
    ) -> Optional[Dict]:
        """
        Send GitHub API request

        Args:
            endpoint: API endpoint (relative to base URL)
            params: Request parameters
            max_retries: Maximum number of retries

        Returns:
            API response JSON dictionary, returns None if failed
        """
        url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
        }

        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, params=params, timeout=30)

                # Update rate limit information
                self.rate_limit_remaining = int(
                    response.headers.get("X-RateLimit-Remaining", 0)
                )
                self.rate_limit_reset = int(
                    response.headers.get("X-RateLimit-Reset", 0)
                )

                # Handle rate limit
                if response.status_code == 403 and self.rate_limit_remaining == 0:
                    reset_time = self.rate_limit_reset
                    wait_time = max(0, reset_time - int(time.time())) + 1
                    print(
                        f"Rate limit exceeded. Waiting {wait_time} seconds until reset..."
                    )
                    time.sleep(wait_time)
                    continue

                # Handle other errors
                if response.status_code != 200:
                    print(
                        f"GitHub API error: {response.status_code} - {response.text[:200]}"
                    )
                    if response.status_code == 422:
                        # 422 Unprocessable Entity - usually query syntax error
                        return None
                    if attempt < max_retries - 1:
                        time.sleep(2**attempt)  # Exponential backoff
                        continue
                    return None

                return response.json()

            except requests.exceptions.RequestException as e:
                print(f"Request error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                return None

        return None

    def search_github_code(
        self,
        query: str,
        language: Optional[str] = "java",
        per_page: int = 30,
        max_results: int = 100,
    ) -> List[Dict]:
        """
        Search code using GitHub API

        Args:
            query: GitHub search query string
            language: Programming language filter, default 'java'
            per_page: Number of results per page (max 100)
            max_results: Maximum number of results to return

        Returns:
            List of search results, each result contains: repository, path, url, html_url, etc.
        """
        if not query or not query.strip():
            return []

        # Build search query (add language filter)
        search_query = query
        if language:
            search_query = f"{query} language:{language}"

        results = []
        page = 1

        while len(results) < max_results:
            # Check rate limit
            if self.rate_limit_remaining is not None and self.rate_limit_remaining <= 0:
                reset_time = self.rate_limit_reset
                wait_time = max(0, reset_time - int(time.time())) + 1
                print(f"Rate limit reached. Waiting {wait_time} seconds...")
                time.sleep(wait_time)

            params = {
                "q": search_query,
                "per_page": min(per_page, 100),
                "page": page,
            }

            response_data = self._make_github_request("search/code", params=params)

            if not response_data:
                break

            items = response_data.get("items", [])
            if not items:
                break

            # Extract required information
            for item in items:
                results.append(
                    {
                        "repository": item.get("repository", {}).get("full_name", ""),
                        "repository_url": item.get("repository", {}).get(
                            "html_url", ""
                        ),
                        "path": item.get("path", ""),
                        "url": item.get("url", ""),
                        "html_url": item.get("html_url", ""),
                        "sha": item.get("sha", ""),
                    }
                )

                if len(results) >= max_results:
                    break

            # Check if there are more pages
            total_count = response_data.get("total_count", 0)
            if len(results) >= total_count or len(items) < per_page:
                break

            page += 1
            time.sleep(1)  # Avoid requesting too fast

        return results

    def _generate_github_search_keywords(
        self,
        pattern: Dict,
        cwe_id: str,
    ) -> str:
        """
        Step 2.7: Generate GitHub search keywords

        Args:
            pattern: Vulnerability pattern dictionary
            cwe_id: CWE ID

        Returns:
            GitHub search query string
        """
        keywords = []

        # Source keywords
        source_keywords = []
        for source in pattern.get("sources", []):
            var = source.get("variable", "")
            if "getParameter" in str(source.get("pattern", "")):
                source_keywords.append("getParameter")
            elif "getHeader" in str(source.get("pattern", "")):
                source_keywords.append("getHeader")
            elif "readObject" in str(source.get("pattern", "")):
                source_keywords.append("readObject")
            elif "new File" in str(source.get("pattern", "")):
                source_keywords.append("new File")

        if source_keywords:
            keywords.append(f"({' OR '.join(set(source_keywords))})")

        # Sink keywords (optimized based on CWE type)
        sink_keywords = []
        for sink in pattern.get("sinks", []):
            sink_pattern = str(sink.get("pattern", ""))
            sink_name = sink.get("sink_name", "")
            vuln_type = sink.get("vuln_type", "")

            # Add keywords based on CWE type and sink type
            if cwe_id == "CWE-79":  # XSS
                if (
                    "println" in sink_pattern
                    or "print" in sink_pattern
                    or sink_name in ["println", "print", "write", "append", "getWriter"]
                ):
                    sink_keywords.append("println")
                    sink_keywords.append("response.getWriter")
                elif "innerHTML" in sink_pattern or "outerHTML" in sink_pattern:
                    sink_keywords.append("innerHTML")
            elif cwe_id == "CWE-22":  # Path Traversal
                if "File" in sink_pattern or sink_name in [
                    "new File",
                    "FileInputStream",
                    "FileOutputStream",
                ]:
                    sink_keywords.append("new File")
                elif (
                    "readAllBytes" in sink_pattern
                    or "readString" in sink_pattern
                    or sink_name in ["Files.readAllBytes", "Files.readString"]
                ):
                    sink_keywords.append("Files.readAllBytes")
                elif "Paths.get" in sink_pattern or sink_name == "Paths.get":
                    sink_keywords.append("Paths.get")
            else:  # Generic pattern
                if "execute" in sink_pattern:
                    sink_keywords.append("Statement.execute")
                elif "println" in sink_pattern or "print" in sink_pattern:
                    sink_keywords.append("println")
                elif "readAllBytes" in sink_pattern or "readString" in sink_pattern:
                    sink_keywords.append("Files.readAllBytes")
                elif "exec" in sink_pattern:
                    sink_keywords.append("Runtime.exec")
                elif "File" in sink_pattern:
                    sink_keywords.append("new File")

        if sink_keywords:
            keywords.append(f"({' OR '.join(set(sink_keywords))})")

        # Taint operation keywords (string concatenation)
        if pattern.get("taint_flows"):
            keywords.append('"+"')  # String concatenation

        # Missing Sanitizers (NOT condition) - optimized based on CWE type
        missing_sanitizers = pattern.get("missing_sanitizers", [])
        not_keywords = []

        if cwe_id == "CWE-79":  # XSS - focus on HTML escaping
            if "escapeHtml" in missing_sanitizers:
                not_keywords.append("escapeHtml")
                not_keywords.append("StringEscapeUtils")
                not_keywords.append("ESAPI")
        elif cwe_id == "CWE-22":  # Path Traversal - focus on path normalization
            if "normalize" in missing_sanitizers:
                not_keywords.append("normalize")
                not_keywords.append("getCanonicalPath")
            if "pathValidation" in missing_sanitizers:
                not_keywords.append("isValidPath")
                not_keywords.append("PathValidator")
        else:  # Generic pattern
            if "PreparedStatement" in missing_sanitizers:
                not_keywords.append("PreparedStatement")
            if "escapeHtml" in missing_sanitizers:
                not_keywords.append("escapeHtml")
            if "normalize" in missing_sanitizers:
                not_keywords.append("normalize")

        query = " AND ".join(keywords) if keywords else ""
        if not_keywords:
            query += " NOT " + " NOT ".join(not_keywords)

        return query

    def generate_github_search_keywords(
        self,
        patterns_df: pd.DataFrame,
        output_dir: Optional[Path] = None,
        top_n: Optional[int] = None,
        save_file: bool = True,
    ) -> pd.DataFrame:
        """
        Generate GitHub search queries for each pattern in DataFrame

        Args:
            patterns_df: DataFrame containing vulnerability patterns, must include 'pattern_dict' and 'cwe_id' columns
            output_dir: Output directory, default None (use output directory under current directory)
            top_n: top_n value, used for generating filename, default None
            save_file: Whether to save file, default True

        Returns:
            Updated DataFrame containing 'github_query' column, and 'pattern_dict' column is removed
        """
        # Check if DataFrame is empty
        if patterns_df.empty:
            logger.warning("patterns_df is empty, cannot generate GitHub queries")
            return patterns_df

        # Check if required columns exist
        if "pattern_dict" not in patterns_df.columns:
            logger.warning("patterns_df missing 'pattern_dict' column")
        if "cwe_id" not in patterns_df.columns:
            logger.warning("patterns_df missing 'cwe_id' column")

        # Generate GitHub queries for each pattern
        github_queries = []
        for _, row in patterns_df.iterrows():
            pattern_dict = row.get("pattern_dict")
            cwe_id = row.get("cwe_id")
            if pattern_dict and cwe_id:
                query = self._generate_github_search_keywords(pattern_dict, cwe_id)
                github_queries.append(query)
            else:
                github_queries.append("")

        # Add github_query column
        result_df = patterns_df.copy()
        result_df["github_query"] = github_queries

        # Remove temporary pattern_dict column (if exists)
        if "pattern_dict" in result_df.columns:
            result_df = result_df.drop(columns=["pattern_dict"])

        # Save file
        if save_file:
            if output_dir is None:
                output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)

            if top_n is not None:
                output_file = output_dir / f"cwe_based_patterns_top{top_n}.csv"
            else:
                output_file = output_dir / "cwe_based_patterns.csv"

            result_df.to_csv(output_file, index=False, encoding="utf-8")
            logger.info(f"Updated pattern records file (includes GitHub queries): {output_file}")

        return result_df

    def search_github_with_queries(
        self,
        patterns_df: pd.DataFrame,
        language: Optional[str] = "java",
        max_results_per_query: int = 100,
        save_results: bool = True,
        output_dir: Optional[str] = None,
    ) -> pd.DataFrame:
        """
        Use generated GitHub queries to call GitHub API for searching

        Args:
            patterns_df: DataFrame containing 'github_query' column
            language: Programming language filter, default 'java'
            max_results_per_query: Maximum number of results per query
            save_results: Whether to save search results to file
            output_dir: Output directory, default None (use current directory)

        Returns:
            DataFrame containing search results, new columns:
            - github_search_results: List of search results (JSON string)
            - github_result_count: Number of results
        """
        if "github_query" not in patterns_df.columns:
            raise ValueError("DataFrame must contain 'github_query' column")

        results_list = []
        result_counts = []

        total_queries = len(patterns_df)
        print(f"\nStarting to call GitHub API to search {total_queries} queries...")

        for idx, row in patterns_df.iterrows():
            query = row.get("github_query", "")
            cwe_id = row.get("cwe_id", "")
            cve_id = row.get("cve_id", "")

            print(
                f"\n[{idx + 1}/{total_queries}] Searching query: {query[:100]}..."
                f" (CWE: {cwe_id}, CVE: {cve_id})"
            )

            if not query or not query.strip():
                results_list.append("[]")
                result_counts.append(0)
                continue

            # Call GitHub API to search
            search_results = self.search_github_code(
                query=query,
                language=language,
                max_results=max_results_per_query,
            )

            # Save results
            import json

            results_json = json.dumps(search_results, ensure_ascii=False)
            results_list.append(results_json)
            result_counts.append(len(search_results))

            print(f"  Found {len(search_results)} results")

            # Display rate limit information
            if self.rate_limit_remaining is not None:
                print(f"  Rate limit remaining: {self.rate_limit_remaining}")

            # Avoid requesting too fast
            time.sleep(1)

        # Add result columns
        result_df = patterns_df.copy()
        result_df["github_search_results"] = results_list
        result_df["github_result_count"] = result_counts

        # Save results
        if save_results:
            if output_dir is None:
                output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)

            output_file = os.path.join(output_dir, "github_search_results.csv")
            result_df.to_csv(output_file, index=False, encoding="utf-8")
            print(f"\nSearch results saved to: {output_file}")

        total_results = sum(result_counts)
        print(f"\nSearch completed! Found {total_results} results in total")

        return result_df
