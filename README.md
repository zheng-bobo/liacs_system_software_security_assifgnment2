# Detecting Recurring Vulnerability Code Patterns

**Leiden University - 2526-S1 System & Software Security - Assignment 2**

**Group Members:**
- Xuzhang Zheng (s4414268)
- Xing He (s4707443)

---

Extract vulnerable code from the MoreFixes database, identify recurring vulnerability patterns, and generate GitHub search queries.

## 📋 Table of Contents

- [Features](#features)
- [Installation and Configuration](#installation-and-configuration)
- [Quick Start](#quick-start)
- [Workflow](#workflow)
- [Module Structure](#module-structure)
- [Usage](#usage)
- [Output Results](#output-results)
- [Related Documentation](#related-documentation)

## ✨ Features

1. **Data Extraction**: Extract high-quality vulnerability fix samples from the MoreFixes database
   - Support for multiple programming languages (default Java)
   - Configurable quality threshold (score >= 65, accuracy ~95%+)
   - Automatically exclude merge commits
   - Support filtering by CWE type (Top N CWE)

2. **Pattern Recognition**: Use source/sink/taint analysis to identify recurring vulnerability patterns
   - Source identification: Identify untrusted input sources (e.g., `getParameter`, `getHeader`, etc.)
   - Sink identification: Identify dangerous usage points (e.g., SQL execution, XSS output, path operations, etc.)
   - Taint flow analysis: Track data propagation paths from source to sink
   - Security measures analysis: Identify missing security measures (e.g., HTML escaping, path normalization, etc.)
   - Support targeted analysis for specific CWE types (CWE-79 XSS, CWE-22 Path Traversal, etc.)

3. **Query Generation**: Generate GitHub search queries for each identified pattern
   - Generate queries based on source/sink keywords
   - Optimize query keywords according to CWE type
   - Support calling GitHub API for actual searching
   - Automatically handle GitHub API rate limits

## 🚀 Installation and Configuration

### Requirements

- Python 3.8+
- PostgreSQL database (MoreFixes database)
- Related Python packages (see `requirements.txt`)
- CodeQL CLI (optional, for patch validation)
- Semgrep CLI (optional, for static analysis)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create a `.env` file and configure database connection information:

```bash
# Create .env file in project root directory
touch .env
```

Edit the `.env` file and set the following variables:

```env
# Database configuration
POSTGRES_USER=your_username
POSTGRES_PASSWORD=your_password
DB_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=morefixes

# GitHub API configuration (optional, but recommended to improve rate limit)
GITHUB_TOKEN=your_github_personal_access_token
```

**Note**: The `.env` file contains sensitive information. Make sure it's added to `.gitignore` and not committed to version control.

### GitHub Token Setup

If you need to use GitHub API search functionality, create a GitHub Personal Access Token:

1. Visit https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select permissions: at least `public_repo` permission is required
4. Copy the generated token and add it to the `.env` file

## 🎯 Quick Start

### Basic Usage

```bash
python vulnerability_pattern_miner.py --top-n 3 --min-score 65 --languages java
```

### Command Line Arguments

- `--top-n`: Return top n CWE types by occurrence count (default: 3)
- `--min-score`: Minimum value of fixes.score (default: 65)
- `--include-merge`: Include merge commits (default: excluded)
- `--languages`: List of programming languages, case-insensitive (default: java)

### Examples

```bash
# Extract top 3 most common Java vulnerability patterns (CWE-79, CWE-22, etc.)
python vulnerability_pattern_miner.py --top-n 3 --languages java

# Extract top 5 most common vulnerability patterns
python vulnerability_pattern_miner.py --top-n 5 --languages java

# Extract vulnerability patterns for multiple languages
python vulnerability_pattern_miner.py --top-n 3 --languages java python go
```

## 📊 Workflow

### Step 1: Data Extraction

Extract high-quality vulnerability fix samples from the database.

**Filter Conditions**:
- `fixes.score >= 65` (high-quality fix samples, accuracy ~95%+)
- `file_change.diff IS NOT NULL` (require code differences)
- `commits.merge = FALSE` (exclude merge commits, default)
- `file_change.programming_language` (support multiple languages, default Java)
- Only include fixes with single file change (`file_change_count = 1`)

**Extracted Fields**:
- `cve_id`: CVE ID
- `hash`: Commit hash
- `repo_url`: Repository URL
- `filename`: Filename
- `code_before`: Code before vulnerability
- `code_after`: Code after fix
- `diff`: Code differences

**Output**: `output/extract_java_vulnerable_code.csv`

### Step 2: CWE Classification and Pattern Recognition

1. **CWE Classification Statistics**: Count CVE numbers for each CWE type, select Top N
2. **Method-level Code Extraction**: Extract method-level code changes from each CVE
3. **Source/Sink/Taint Analysis**:
   - Identify untrusted input sources (Source)
   - Identify dangerous usage points (Sink)
   - Track data flow (Taint Flow)
   - Analyze missing security measures
4. **Pattern Filtering**: Adjust filter conditions based on CWE type
   - CWE-79 (XSS) and CWE-22 (Path Traversal): Require complete source → sink → taint flow
   - NVD-CWE-noinfo: Relax conditions, only need source and sink

**Output**: `output/cwe_based_patterns_top{n}.csv` and `output/top_cwe_top{n}.csv`

### Step 3: GitHub Query Generation

Generate GitHub search queries for each identified pattern:

1. **Query Generation**: Generate query strings based on source/sink keywords
2. **CWE Type Optimization**: Optimize keyword selection based on CWE type
3. **File Saving**: Automatically save DataFrame containing queries

**Output**: `output/cwe_based_patterns_top{n}.csv` (includes `github_query` column)

### Step 4: GitHub Code Search (Optional)

There are two ways to search GitHub code:

#### Option A: Using `github_code_scraper.py` (Recommended)

Automated GitHub code search with TF-IDF keyword expansion:

1. **Automated Search**: Uses GitHub Code Search API to find vulnerable code patterns
2. **TF-IDF Expansion**: Automatically expands search keywords using TF-IDF from downloaded code
3. **Recursive Search**: Supports recursive keyword expansion to find more variants
4. **State Management**: Supports pause/resume with state saving
5. **Code Download**: Automatically downloads code files for TF-IDF analysis

**Usage**:
```bash
python3 github_code_scraper.py --input-file output/cwe_based_patterns_top3.csv --language java
```

**Output**: Results are displayed in console (no CSV file generated)

#### Option B: Using `github_query_generator.py` API

Direct GitHub API search using the query generator:

1. **Batch Search**: Iterate through all generated queries
2. **Result Extraction**: Extract repository, file path, URL, and other information
3. **Rate Limit Handling**: Automatically handle API limits
4. **Result Saving**: Results are returned in DataFrame (no CSV file generated)

## 📁 Module Structure

```
liacs_system_software_security/
├── vulnerability_pattern_miner.py       # Main program entry point
├── github_query_generator.py             # GitHub query generation and API call module
├── github_code_scraper.py                # Automated GitHub code search with TF-IDF expansion
├── extract_github_queries.py           # Extract and display GitHub queries
├── regenerate_github_queries.py          # Regenerate GitHub queries from patterns
├── DATABASE_TABLES_EXPLANATION.md       # Database table structure documentation
├── VULNERABILITY_PATTERN_MINING.md      # Vulnerability pattern mining workflow documentation
├── GITHUB_SEARCH_GUIDE.md               # GitHub search usage guide
├── requirements.txt                     # Python dependency package list
├── docker-compose.yml                   # Docker configuration (optional)
└── output/                              # Output directory
    ├── extract_java_vulnerable_code.csv
    ├── top_cwe_top{n}.csv
    ├── cwe_based_patterns_top{n}.csv
    ├── pattern_instances.csv
    ├── github_query.csv
    └── github_search_results.csv
```

### Main Module Descriptions

#### `vulnerability_pattern_miner.py`
Main program file, includes:
- `DatabaseConnector`: Database connector
- `extract_java_vulnerable_code()`: Extract vulnerable code from database (supports Top N CWE filtering)
- `process_cwe_based_patterns()`: CWE-based pattern recognition
- `extract_vulnerability_pattern()`: Extract vulnerability patterns (source/sink/taint analysis)
- `analyze_source_sink_taint()`: Analyze source, sink, and taint flows
- `analyze_missing_security()`: Analyze missing security measures
- `main()`: Main function, coordinates the entire workflow

#### `github_query_generator.py`
GitHub query generation and API call module, includes:
- `GitHubQueryGenerator`: GitHub query generator class
- `generate_github_search_keywords()`: Generate GitHub queries for DataFrame and save file
- `search_github_code()`: Search code using GitHub API
- `search_github_with_queries()`: Batch call GitHub API for searching
- `_make_github_request()`: Low-level API request handling (includes rate limit handling)
- `_generate_github_search_keywords()`: Generate query strings from vulnerability patterns (GitHub API compatible syntax)

#### `github_code_scraper.py`
Automated GitHub code search with TF-IDF keyword expansion, based on DotDotDefender's recursive-scrapper.py logic:
- `scrape_github_code()`: Main function to search GitHub code from CSV queries
- `find_repos()`: Recursive repository search with keyword expansion
- `search_code()`: Paginated GitHub Code Search API calls
- `compute_tfidf()`: TF-IDF keyword extraction from downloaded code
- `download_code_file()`: Download code files for TF-IDF analysis
- State saving and recovery support

## 💻 Usage

### Python API

```python
from pathlib import Path
from vulnerability_pattern_miner import (
    DatabaseConnector,
    extract_java_vulnerable_code,
    process_cwe_based_patterns,
    main
)
from github_query_generator import GitHubQueryGenerator

# Initialize database connection
db_connector = DatabaseConnector()

# Extract vulnerable code (includes Top N CWE filtering)
vulnerable_code_df = extract_java_vulnerable_code(
    db_connector,
    min_score=65,
    exclude_merge_commits=True,
    programming_languages=["Java"],
    require_diff=True,
    top_n=3,  # Only extract data for Top 3 CWE
    output_dir=Path("output")
)

# Identify recurring patterns (CWE-based)
recurring_patterns_df = process_cwe_based_patterns(
    vulnerable_code_df,
    db_connector,
    top_n=3,
    min_score=65,
    programming_languages=["Java"],
    output_dir=Path("output")
)

# Generate GitHub queries
query_generator = GitHubQueryGenerator()
recurring_patterns_df = query_generator.generate_github_search_keywords(
    recurring_patterns_df,
    output_dir=Path("output"),
    top_n=3,
    save_file=True
)

# Option A: Use github_code_scraper.py for automated search (recommended)
# This includes TF-IDF keyword expansion and recursive search
import subprocess
subprocess.run([
    "python3", "github_code_scraper.py",
    "--input-file", "output/cwe_based_patterns_top3.csv",
    "--language", "java",
    "--min-stars", "100",
    "--max-results-per-query", "1000"
])

# Option B: Use github_query_generator.py API directly
if len(recurring_patterns_df) > 0:
    results_df = query_generator.search_github_with_queries(
        recurring_patterns_df,
        language="java",
        max_results_per_query=100,
        save_results=True,
        output_dir="output"
    )
```

### Run Main Program Directly

```python
from vulnerability_pattern_miner import main

main(
    top_n=3,
    min_score=65,
    exclude_merge_commits=True,
    programming_languages=["Java"],
    require_diff=True
)
```

## 📤 Output Results

### Raw Data (`extract_java_vulnerable_code.csv`)

Contains the following fields:
- `cve_id`: CVE ID
- `hash`: Commit hash
- `repo_url`: Repository URL
- `filename`: Filename
- `score`: Fix quality score
- `programming_language`: Programming language
- `diff`: Code differences

### Top CWE List (`top_cwe_top{n}.csv`)

Contains the following fields:
- `cwe_id`: CWE ID
- `cwe_name`: CWE name
- `fix_count`: Number of fixes for this CWE

### Pattern Records (`cwe_based_patterns_top{n}.csv`)

Contains the following fields:
- `cwe_id`: CWE ID
- `cwe_name`: CWE name
- `cve_id`: CVE ID
- `file_change_id`: File change ID
- `method_change_id`: Method change ID
- `method_name`: Method name
- `signature`: Method signature
- `sources`: Source list (JSON string)
- `sinks`: Sink list (JSON string)
- `taint_flows`: Taint flow list (JSON string)
- `tainted_variables`: List of tainted variables (JSON string)
- `missing_sanitizers`: List of missing sanitizers (JSON string)
- `added_security_measures`: List of added security measures (JSON string)
- `github_query`: GitHub search query string
- `method_code`: Method code (first 500 characters)

### Pattern Instances (`pattern_instances.csv`)

Contains detailed instance-level information for each vulnerability pattern occurrence:
- `pattern_key`: Unique pattern identifier (combines CWE, sink types, and source types)
- `cwe_id`: CWE ID
- `cwe_name`: CWE name
- `sink_types`: Comma-separated list of sink types
- `source_types`: Comma-separated list of source types
- `missing_sanitizers`: List of missing sanitizers (JSON string)
- `cve_id`: CVE ID
- `hash`: Commit hash
- `repo_url`: Repository URL
- `commit_link`: Full commit URL
- `method_name`: Method name
- `signature`: Method signature
- `code_diff`: Code differences (patch format)
- `github_query`: GitHub search query string

This file contains one row per vulnerability instance, allowing detailed analysis of pattern occurrences across different CVEs and repositories.

### GitHub Query List (`github_query.csv`)

Contains a simplified list of GitHub search queries grouped by CWE:
- `cwe_id`: CWE ID
- `cwe_name`: CWE name
- `github_query`: GitHub search query string

This file provides a quick reference of all generated GitHub queries organized by vulnerability type, useful for manual searching or batch processing.

### GitHub Search Results (`github_search_results.csv`)

If GitHub API is called, this file will be generated, containing:
- All pattern record fields
- `github_search_results`: List of search results (JSON string)
- `github_result_count`: Number of results

Each search result contains:
- `repository`: Repository full name (e.g., `owner/repo`)
- `repository_url`: Repository URL
- `path`: File path
- `url`: API URL
- `html_url`: GitHub web page URL
- `sha`: File SHA

## 🔧 Configuration

### CWE Type Support

Currently supports targeted analysis for the following CWE types:

- **CWE-79**: Cross-site Scripting (XSS)
  - Focus on XSS sinks (println, print, innerHTML, etc.)
  - Check HTML escaping security measures

- **CWE-22**: Path Traversal
  - Focus on file operation sinks (new File, Files.readAllBytes, etc.)
  - Check path normalization security measures

- **NVD-CWE-noinfo**: Insufficient Information
  - Use generic pattern matching
  - Relax filter conditions

### GitHub API Rate Limit

- **Unauthenticated**: 60 requests/hour
- **Authenticated**: 5000 requests/hour (requires setting `GITHUB_TOKEN`)

The program automatically handles rate limits and will wait for reset when the limit is reached.

### Performance Optimization

- Use `top_n` parameter to limit the number of CWE types processed
- For large datasets, recommend testing with small-scale data first
- GitHub API search may take a long time, recommend running in background

## 📝 Example Output

After running the program, statistics will be output to the console:

```
============================================================
Statistics:
  Total records: 1234
  Unique CVE count: 567
  Unique commit count: 890
  Unique repository count: 234
  Unique file count: 456
  Identified recurring patterns: 45
  Generated GitHub queries: 45
============================================================
```

## 📚 Related Documentation

- [DATABASE_TABLES_EXPLANATION.md](DATABASE_TABLES_EXPLANATION.md): Detailed database table structure documentation
- [VULNERABILITY_PATTERN_MINING.md](VULNERABILITY_PATTERN_MINING.md): Complete vulnerability pattern mining workflow documentation

## 🔍 Supported CWE Types

Currently mainly supports the following Top 3 CWE types:

1. **CWE-79**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
2. **NVD-CWE-noinfo**: Insufficient Information
3. **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## ⚠️ Notes

1. **Database Connection**: Ensure database connection configuration is correct and database is accessible
2. **GitHub Token**: If using GitHub API, recommend setting token to improve rate limit
3. **Data Volume**: Processing large amounts of data may take a long time, recommend testing with small-scale data first
4. **API Limits**: GitHub API has rate limits, program will handle automatically, but may need to wait
