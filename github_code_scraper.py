#!/usr/bin/env python3
"""
GitHub Code Scraper - Search GitHub code based on vulnerability patterns

Features:
1. Read vulnerability patterns and GitHub queries from CSV files
2. Expand search keywords using TF-IDF
3. Recursively search GitHub Code Search API
4. Save search results to CSV files
5. Support state saving and recovery

Based on DotDotDefender's recursive-scrapper.py logic

Usage:
    # Basic usage
    python3 github_code_scraper.py --input-file output/cwe_based_patterns_top3.csv --language java

    # Specify output file
    python3 github_code_scraper.py --input-file output/cwe_based_patterns_top3.csv --language java --output-file output/github_search_results.csv

    # Set minimum stars
    python3 github_code_scraper.py --input-file output/cwe_based_patterns_top3.csv --language java --min-stars 100

    # Limit maximum results per query
    python3 github_code_scraper.py --input-file output/cwe_based_patterns_top3.csv --language java --max-results-per-query 500
"""

import random
import requests
import json
import os
import glob
import re
import time
import logging
import nltk
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Set
from sklearn.feature_extraction.text import TfidfVectorizer
from nltk.tokenize import RegexpTokenizer
import argparse
from dotenv import load_dotenv

# Ensure NLTK tokens are downloaded
try:
    nltk.download("punkt", quiet=True)
except:
    pass

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("github_code_scraper.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# GitHub API Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SEARCH_API_URL = "https://api.github.com/search/code"
HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
# Default values (can be overridden by command line arguments)
DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 5


def gh_url_to_raw(url: str) -> str:
    """Convert GitHub blob URL to raw URL"""
    return re.sub("blob/[a-fA-F0-9]+", "HEAD", url).replace(
        "github.com", "raw.githubusercontent.com"
    )


def make_safe_filename(s: str) -> str:
    """Generate safe filename"""
    return re.sub(r"[^a-zA-Z0-9_\.-]", "_", s)


def get_rate_limit_reset_time(headers) -> int:
    """Get rate limit reset time"""
    return int(headers.get("X-RateLimit-Reset", 0))


def get_rate_limit_remaining(headers) -> int:
    """Get remaining rate limit"""
    return int(headers.get("X-RateLimit-Remaining", 0))


def get_repo_details(repo_api_url: str) -> Dict:
    """Get repository details including star count"""
    response = requests.get(repo_api_url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    return {}


def download_code_file(file_url: str, output_path: str) -> bool:
    """
    Download code file from GitHub raw URL

    Args:
        file_url: Raw file URL from GitHub
        output_path: Local path to save the file

    Returns:
        True if download successful, False otherwise
    """
    try:
        response = requests.get(file_url, headers=HEADERS, timeout=30)
        if response.status_code == 200:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(response.content)
            return True
        else:
            logger.debug(f"Failed to download {file_url}: HTTP {response.status_code}")
            return False
    except Exception as e:
        logger.warning(f"Error downloading {file_url}: {e}")
        return False


def extract_matching_code_snippet(
    file_url: str, query_terms: List[str], context_lines: int = 3
) -> str:
    """
    Fetch code content and extract matching lines with context

    Args:
        file_url: Raw file URL from GitHub
        query_terms: List of search terms to match
        context_lines: Number of context lines before and after match

    Returns:
        Matching code snippet as string, empty string if failed
    """
    try:
        response = requests.get(file_url, headers=HEADERS, timeout=30)
        if response.status_code != 200:
            logger.debug(f"Failed to fetch {file_url}: HTTP {response.status_code}")
            return ""

        # Try to decode as UTF-8, fallback to latin-1 if fails
        try:
            code_content = response.text
        except UnicodeDecodeError:
            code_content = response.content.decode("latin-1", errors="ignore")

        if not code_content:
            return ""

        lines = code_content.split("\n")
        matched_indices = set()

        # Find lines that contain any of the query terms
        for i, line in enumerate(lines):
            line_lower = line.lower()
            for term in query_terms:
                if term.lower() in line_lower:
                    matched_indices.add(i)
                    break

        if not matched_indices:
            return ""

        # Collect all lines to include (matched lines + context)
        lines_to_include = set()
        for idx in matched_indices:
            # Add context lines before
            start = max(0, idx - context_lines)
            # Add context lines after
            end = min(len(lines), idx + context_lines + 1)
            # Add all lines in this range
            for i in range(start, end):
                lines_to_include.add(i)

        # Extract all matching and context lines in order
        result_lines = []
        last_idx = -1
        for idx in sorted(lines_to_include):
            # Add separator if there's a gap (more than context_lines*2+1 lines apart)
            if last_idx >= 0 and idx - last_idx > context_lines * 2 + 1:
                result_lines.append("...")
            result_lines.append(lines[idx])
            last_idx = idx

        return "\n".join(result_lines)

    except Exception as e:
        logger.warning(f"Error extracting code snippet from {file_url}: {e}")
        return ""


def tokenize_code(content: str) -> List[str]:
    """
    Tokenize source code content
    """
    tokenizer = RegexpTokenizer(r"\w+")
    return tokenizer.tokenize(content)


def compute_tfidf(directory_path: str, lang: str, base_query: str) -> List[tuple]:
    """
    Compute TF/IDF for files in directory, return sorted list of (term, score) tuples
    """
    if not os.path.exists(directory_path):
        logger.warning(f"Directory does not exist: {directory_path}")
        return []

    # Initialize TfidfVectorizer
    vectorizer = TfidfVectorizer(tokenizer=tokenize_code, lowercase=True, binary=True)

    # Read all file contents
    file_contents = []
    pattern = os.path.join(directory_path, f"*.{lang}")
    for filepath in glob.glob(pattern):
        if os.path.isfile(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    file_contents.append(f.read())
            except Exception as e:
                logger.warning(f"Failed to read file {filepath}: {e}")

    if not file_contents:
        logger.warning(f"No {lang} files found in directory {directory_path}")
        return []

    # Compute TF/IDF
    try:
        tfidf_matrix = vectorizer.fit_transform(file_contents)
        sums = tfidf_matrix.sum(axis=0)

        # Connect terms with their frequencies
        terms = vectorizer.get_feature_names_out()
        scores = [
            (term, sums[0, idx]) for term, idx in zip(terms, range(sums.shape[1]))
        ]

        # Sort by score
        sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)
        base_query_terms = base_query.lower().split(" ")
        return list(
            filter(
                lambda item: item[0].lower() not in base_query_terms
                and len(item[0]) > 2,  # Filter words that are too short
                sorted_scores,
            )
        )
    except Exception as e:
        logger.error(f"TF-IDF computation failed: {e}")
        return []


def search_code(
    query: str,
    lang: str,
    page: int,
    items: List[Dict],
    max_pages: int = DEFAULT_MAX_PAGES,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> None:
    """Search code snippets with pagination"""
    logger.info(f"Parsing page {page}, query: {query}")
    params = {
        "q": f"language:{lang} {query}",
        "per_page": page_size,
        "page": page,
    }
    # Note: GitHub API doesn't support text_match parameter in search/code endpoint
    # We'll extract code snippets from the file content later

    try:
        response = requests.get(
            SEARCH_API_URL, headers=HEADERS, params=params, timeout=30
        )

        # Handle rate limiting - check before and after request
        rate_limit_remaining = get_rate_limit_remaining(response.headers)

        # If 403 Forbidden (rate limit exceeded), wait and retry
        if response.status_code == 403:
            reset_time = get_rate_limit_reset_time(response.headers)
            if reset_time > 0:
                sleep_time = max(0, reset_time - time.time()) + 5  # Add 5 second buffer
                logger.warning(
                    f"Rate limit exceeded (403), waiting {sleep_time:.0f} seconds until reset..."
                )
                if sleep_time > 0:
                    time.sleep(sleep_time)
                # Retry request after waiting
                response = requests.get(
                    SEARCH_API_URL, headers=HEADERS, params=params, timeout=30
                )
            else:
                # If no reset time in headers, wait 60 seconds
                logger.warning(
                    "Rate limit exceeded but no reset time found, waiting 60 seconds..."
                )
                time.sleep(60)
                response = requests.get(
                    SEARCH_API_URL, headers=HEADERS, params=params, timeout=30
                )

        # Handle rate limiting - check remaining quota
        rate_limit_remaining = get_rate_limit_remaining(response.headers)
        if rate_limit_remaining <= 1:
            reset_time = get_rate_limit_reset_time(response.headers)
            sleep_time = max(0, reset_time - time.time()) + 2  # Add 2 second buffer
            logger.warning(
                f"Rate limit low ({rate_limit_remaining} remaining), waiting {sleep_time:.0f} seconds..."
            )
            if sleep_time > 0:
                time.sleep(max(sleep_time, 61))
            # Retry request
            response = requests.get(
                SEARCH_API_URL, headers=HEADERS, params=params, timeout=30
            )

        if response.status_code != 200:
            logger.error(
                f"GitHub API error: {response.status_code} - {response.text[:200]}"
            )
            # If still 403 after retry, wait longer and return
            if response.status_code == 403:
                logger.error("Still rate limited after retry, skipping this query")
            return

        response_data = response.json()
        items.extend(response_data.get("items", []))

        # Check if there are more pages
        if "Link" in response.headers:
            links = response.headers["Link"].split(", ")
            next_link = [link for link in links if 'rel="next"' in link]
            if len(next_link) == 0 or page >= max_pages:
                return
            logger.info("Continuing to next page...")
            time.sleep(1)  # Avoid requesting too fast
            search_code(query, lang, page + 1, items, max_pages, page_size)
    except Exception as e:
        logger.error(f"Search error: {e}")
        logger.info("Waiting 60 seconds before retry...")
        time.sleep(60)
        search_code(query, lang, page, items, max_pages, page_size)


def find_repos(
    lang: str,
    base_query: str,
    keyword_index: int,
    keywords: List[tuple],
    max_pages: int = DEFAULT_MAX_PAGES,
    max_results: int = None,
    tried_words: Set[str] = None,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> List[Dict]:
    """
    Find repositories with keyword expansion support

    Args:
        lang: Programming language
        base_query: Base query string (accumulates keywords as recursion deepens)
        keyword_index: Current keyword index
        keywords: List of (keyword, score) tuples
        max_pages: Maximum pages to search
        max_results: Maximum results to return (None for no limit)
        tried_words: Set of already tried keyword combinations
        page_size: Number of results per page

    Returns:
        List of search result items
    """
    if tried_words is None:
        tried_words = set()

    items = []
    current_query = base_query

    # Add keyword to query if available
    if keyword_index < len(keywords):
        keyword = keywords[keyword_index][0]
        # Check if this keyword combination has been tried
        query_with_keyword = f"{base_query} {keyword}"
        if query_with_keyword in tried_words:
            logger.debug(f"Skipping already tried query: {query_with_keyword}")
            return []
        tried_words.add(query_with_keyword)
        current_query = query_with_keyword

    logger.info(f"Current query: {current_query}")
    search_code(current_query, lang, 1, items, max_pages, page_size)

    # Apply max_results limit
    if max_results is not None and len(items) > max_results:
        items = items[:max_results]
        logger.info(f"Limited results to {max_results} items")

    if len(items) == 0:
        logger.info("No results found...")
        return []

    # If results reach max pages, try adding more keywords
    if len(items) >= (page_size * max_pages):
        logger.info(f"Too many results ({len(items)}), trying to add more keywords...")
        if keyword_index + 1 < len(keywords):
            # Prevent duplicate queries
            next_keyword = keywords[keyword_index + 1][0]
            if next_keyword not in current_query:
                extended_query = f"{current_query} {next_keyword}"
                # Use extended_query instead of base_query to accumulate keywords
                additional_items = find_repos(
                    lang,
                    extended_query,
                    keyword_index + 2,
                    keywords,
                    max_pages,
                    max_results,
                    tried_words,
                    page_size,
                )
                # Merge results (deduplicate)
                existing_repos = {item["repository"]["full_name"] for item in items}
                for item in additional_items:
                    if item["repository"]["full_name"] not in existing_repos:
                        items.append(item)
                        # Apply max_results limit after merging
                        if max_results is not None and len(items) >= max_results:
                            items = items[:max_results]
                            break

    return items


def save_state(
    state_file: str, repos: List[str], repo_details: Dict, tried_words: List[str]
) -> None:
    """Save state to file"""
    try:
        with open(state_file, "w") as f:
            json.dump(
                {
                    "REPOS": repos,
                    "REPO_DETAILS": repo_details,
                    "TRIED_WORDS": tried_words,
                },
                f,
                indent=2,
            )
        logger.info(f"State saved to {state_file}")
    except Exception as e:
        logger.error(f"Failed to save state: {e}")


def load_state(state_file: str) -> tuple:
    """Load state from file"""
    if not os.path.isfile(state_file):
        return [], {}, []

    try:
        with open(state_file, "r") as f:
            state = json.load(f)
        return (
            state.get("REPOS", []),
            state.get("REPO_DETAILS", {}),
            state.get("TRIED_WORDS", []),
        )
    except Exception as e:
        logger.error(f"Failed to load state: {e}")
        return [], {}, []


def scrape_github_code(
    input_file: str,
    output_file: str,
    language: str = "java",
    min_stars: int = 100,
    max_results_per_query: int = 1000,
    use_tfidf: bool = True,
    downloads_dir: str = "downloads",
    state_file: str = "scraper_state.json",
    page_size: int = DEFAULT_PAGE_SIZE,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> None:
    """
    Main function: Read queries from CSV file and search GitHub code

    Args:
        input_file: Input CSV file path
        output_file: Output CSV file path
        language: Programming language
        min_stars: Minimum GitHub stars count
        max_results_per_query: Maximum results per query
        use_tfidf: Whether to use TF-IDF for keyword expansion
        downloads_dir: Directory for downloaded files
        state_file: State file path
        page_size: Number of results per page
        max_pages: Maximum pages to search per query
    """
    # Read CSV file
    try:
        df = pd.read_csv(input_file)
        logger.info(f"Successfully read {len(df)} records")
    except Exception as e:
        logger.error(f"Failed to read CSV file: {e}")
        return

    # Check required columns
    if "github_query" not in df.columns:
        logger.error("CSV file does not contain 'github_query' column")
        return

    # Create downloads directory
    if not os.path.exists(downloads_dir):
        os.makedirs(downloads_dir)

    # Load previous state
    REPOS: List[str] = []
    REPO_DETAILS: Dict[str, Dict] = {}
    TRIED_WORDS: List[str] = []

    if os.path.exists(state_file):
        REPOS, REPO_DETAILS, TRIED_WORDS = load_state(state_file)
        logger.info(
            f"Loaded state: {len(REPOS)} repositories, {len(TRIED_WORDS)} tried keywords"
        )

    # Convert TRIED_WORDS to set for efficient lookup
    TRIED_WORDS_SET = set(TRIED_WORDS)

    # Prepare results list
    all_results = []

    # Compute keywords using TF-IDF if enabled
    keywords = []
    if use_tfidf:
        lang_ext = {
            "java": "java",
            "javascript": "js",
            "python": "py",
            "typescript": "ts",
        }.get(language.lower(), language.lower())

        # Check if downloads directory exists and has files
        if os.path.exists(downloads_dir):
            # Use first query as base query for TF-IDF computation
            first_query = df.iloc[0]["github_query"] if len(df) > 0 else ""
            if first_query and pd.notna(first_query):
                keywords = compute_tfidf(downloads_dir, lang_ext, str(first_query))
                logger.info(
                    f"TF-IDF computation completed, found {len(keywords)} keywords"
                )
            else:
                logger.warning(
                    "TF-IDF enabled but no base query available, skipping TF-IDF"
                )
        else:
            logger.info(
                f"TF-IDF enabled but downloads directory '{downloads_dir}' does not exist. "
                f"Code files will be downloaded during search and used for TF-IDF in subsequent runs."
            )

    # Process each query
    for idx, row in df.iterrows():
        query = row.get("github_query", "")
        cwe_id = row.get("cwe_id", "Unknown")
        cwe_name = row.get("cwe_name", "")
        pattern_key = row.get("pattern_key", "")

        if pd.isna(query) or not str(query).strip():
            logger.warning(f"Row {idx+1} query is empty, skipping")
            continue

        query = str(query).strip()
        logger.info(f"\n{'='*80}")
        logger.info(f"Processing query #{idx+1}/{len(df)}")
        logger.info(f"CWE: {cwe_id} - {cwe_name}")
        logger.info(f"Query: {query}")
        logger.info(f"Minimum stars filter: {min_stars}")
        logger.info(f"{'='*80}")

        # Search code with max_results limit
        items = find_repos(
            language,
            query,
            0,
            keywords[:10] if keywords else [],
            max_pages,
            max_results=max_results_per_query,
            tried_words=TRIED_WORDS_SET,
            page_size=page_size,
        )

        if not items:
            logger.warning("No results found")
            continue

        logger.info(f"Found {len(items)} code snippets")

        # Process each result
        found_repos = {}
        downloaded_count = 0

        for item in items:
            repo_name = item["repository"]["full_name"]

            # Deduplicate
            if repo_name in REPOS:
                continue

            # Get repository details (including stars)
            repo_api_url = item["repository"]["url"]
            repo_info = get_repo_details(repo_api_url)
            stars = repo_info.get("stargazers_count", 0)

            if stars < min_stars:
                logger.info(
                    f"Repository {repo_name} stars ({stars}) < {min_stars}, skipping"
                )
                continue

            # Save repository information
            REPOS.append(repo_name)
            REPO_DETAILS[repo_name] = item

            # Download code file for TF-IDF (if enabled)
            if use_tfidf:
                file_url = gh_url_to_raw(item["html_url"])
                file_path = item["path"]
                # Create safe filename
                safe_repo_name = make_safe_filename(repo_name)
                safe_file_path = make_safe_filename(file_path)
                lang_ext = {
                    "java": "java",
                    "javascript": "js",
                    "python": "py",
                    "typescript": "ts",
                }.get(language.lower(), language.lower())

                # Only download if file has the expected extension
                if file_path.endswith(f".{lang_ext}"):
                    download_path = os.path.join(
                        downloads_dir, f"{safe_repo_name}_{safe_file_path}"
                    )
                    if download_code_file(file_url, download_path):
                        downloaded_count += 1

            # Extract matching code snippet
            file_url = gh_url_to_raw(item["html_url"])
            # Extract query terms (remove NOT, language: etc.)
            query_terms = [
                term.strip()
                for term in query.replace("NOT", " ").replace("language:", " ").split()
                if term.strip() and len(term.strip()) > 2
            ]
            code_snippet = extract_matching_code_snippet(
                file_url, query_terms, context_lines=3
            )

            # Prepare result record
            result = {
                "pattern_key": pattern_key,
                "cwe_id": cwe_id,
                "cwe_name": cwe_name,
                "github_query": query,
                "repository": repo_name,
                "repository_url": item["repository"]["html_url"],
                "path": item["path"],
                # "url": item["url"],
                "html_url": item["html_url"],
                "sha": item.get("sha", ""),
                "stars": stars,
                # "file_url": file_url,
                "code_snippet": code_snippet,
            }
            all_results.append(result)
            found_repos[repo_name] = item

        logger.info(f"Added {len(found_repos)} qualified repositories")
        if use_tfidf and downloaded_count > 0:
            logger.info(f"Downloaded {downloaded_count} code files for TF-IDF")

        # Periodically save state
        if (idx + 1) % 5 == 0:
            # Convert TRIED_WORDS_SET back to list for saving
            TRIED_WORDS = list(TRIED_WORDS_SET)
            save_state(state_file, REPOS, REPO_DETAILS, TRIED_WORDS)

    # Save final state
    TRIED_WORDS = list(TRIED_WORDS_SET)
    save_state(state_file, REPOS, REPO_DETAILS, TRIED_WORDS)

    # Save results to CSV
    if all_results:
        results_df = pd.DataFrame(all_results)

        # Append data if output file exists
        if os.path.exists(output_file):
            try:
                existing_df = pd.read_csv(output_file)
                results_df = pd.concat([existing_df, results_df], ignore_index=True)
                # Deduplicate (based on repository + path)
                results_df = results_df.drop_duplicates(
                    subset=["repository", "path"], keep="last"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to read existing results file: {e}, will create new file"
                )

        results_df.to_csv(output_file, index=False)
        logger.info(f"\n✓ Search results saved to: {output_file}")
        logger.info(f"  Total found {len(results_df)} code snippets")
        logger.info(f"  Involving {results_df['repository'].nunique()} repositories")
    else:
        logger.warning("No results found")


def main():
    parser = argparse.ArgumentParser(
        description="Search GitHub code based on vulnerability patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python3 github_code_scraper.py --input-file output/cwe_based_patterns_top3.csv --language java

  # Specify output file and minimum stars
  python3 github_code_scraper.py \\
      --input-file output/cwe_based_patterns_top3.csv \\
      --language java \\
      --output-file output/github_search_results.csv \\
      --min-stars 100

  # Disable TF-IDF expansion
  python3 github_code_scraper.py \\
      --input-file output/cwe_based_patterns_top3.csv \\
      --language java \\
      --no-tfidf
        """,
    )

    parser.add_argument(
        "--input-file",
        type=str,
        required=True,
        help="Input CSV file path (must contain 'github_query' column)",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default="output/github_search_results.csv",
        help="Output CSV file path (default: output/github_search_results.csv)",
    )
    parser.add_argument(
        "--language",
        type=str,
        default="java",
        help="Programming language (default: java)",
    )
    parser.add_argument(
        "--min-stars",
        type=int,
        default=100,
        help="Minimum GitHub stars count (default: 100)",
    )
    parser.add_argument(
        "--max-results-per-query",
        type=int,
        default=1000,
        help="Maximum results per query (default: 1000)",
    )
    parser.add_argument(
        "--downloads-dir",
        type=str,
        default="downloads",
        help="Directory for downloaded files (for TF-IDF, default: downloads)",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default="scraper_state.json",
        help="State file path (default: scraper_state.json)",
    )
    parser.add_argument(
        "--no-tfidf",
        action="store_true",
        help="Disable TF-IDF keyword expansion",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"Number of results per page (default: {DEFAULT_PAGE_SIZE})",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=f"Maximum pages to search per query (default: {DEFAULT_MAX_PAGES})",
    )

    args = parser.parse_args()

    # Check input file
    if not os.path.exists(args.input_file):
        logger.error(f"Input file does not exist: {args.input_file}")
        return

    # Check GitHub Token
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not configured, rate limit is 60 requests/hour")
        logger.warning(
            "Recommend configuring GITHUB_TOKEN in .env file for higher rate limit (5000 requests/hour)"
        )
        response = input("\nContinue? (y/n): ")
        if response.lower() != "y":
            logger.info("Cancelled")
            return

    # Create output directory
    output_dir = os.path.dirname(args.output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Execute search
    scrape_github_code(
        input_file=args.input_file,
        output_file=args.output_file,
        language=args.language,
        min_stars=args.min_stars,
        max_results_per_query=args.max_results_per_query,
        use_tfidf=not args.no_tfidf,
        downloads_dir=args.downloads_dir,
        state_file=args.state_file,
        page_size=args.page_size,
        max_pages=args.max_pages,
    )


if __name__ == "__main__":
    main()
