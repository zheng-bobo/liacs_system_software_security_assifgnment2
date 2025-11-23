# MoreFixes Database Tables Documentation

This document provides detailed explanations of the purpose, field meanings, and data content of each table in the MoreFixes database.

## Database Overview

The database contains **12 tables**, storing over **1 million records** in total, covering CVE vulnerability information, code fix records, repository information, etc.

## Table Statistics

| Table Name | Record Count | Description |
|------------|--------------|-------------|
| fixes | 464,296 | Vulnerability fix records |
| cve | 249,380 | CVE vulnerability information |
| cwe_classification | 253,162 | CVE-CWE classification mapping |
| cve_cpe_mapper | 343,949 | CVE-CPE mapping relationships |
| method_change | 229,511 | Method-level code changes |
| file_change | 103,703 | File-level code changes |
| cve_project | 92,467 | CVE-project associations |
| commits | 39,022 | Git commit records |
| repository | 7,238 | Code repository information |
| cpe_project | 11,883 | CPE-project associations |
| cwe | 1,376 | CWE weakness type definitions |
| users | 0 | User table (currently empty) |

---

## Core Tables Detailed Explanation

### 1. `fixes` - Vulnerability Fix Records Table
**Record Count**: 464,296  
**Purpose**: Stores fix commit records corresponding to each CVE, one of the core tables in the database.

**Field Descriptions**:
- `cve_id` (text): CVE ID, e.g., "CVE-2020-28620"
- `hash` (text): Git commit hash, the commit ID that fixes the vulnerability
- `repo_url` (text): Code repository URL, e.g., "https://github.com/CGAL/cgal"
- `rel_type` (text): Relationship type, indicates how the CVE is associated with the fix commit (see rel_type explanation below)
- `score` (bigint): Association score, higher values indicate higher association (typically >= 65)
- `extraction_status` (text): Extraction status, defaults to 'NOT_STARTED'

**Data Example**:
```
CVE-2020-28620 | e1870c15224ddd5d79b1df5b8248e4c6813d7398 | https://github.com/CGAL/cgal | CPE_GIT_REPOBASED | 82
```

**Relationships**:
- Related to `commits` table via `hash` and `repo_url`
- Related to `cve` table via `cve_id`

---

### 2. `commits` - Git Commit Records Table
**Record Count**: 39,022  
**Purpose**: Stores detailed Git commit information, including author, commit message, code change statistics, etc.

**Field Descriptions**:
- `hash` (text): Git commit hash (one of the primary keys)
- `repo_url` (text): Code repository URL (one of the primary keys)
- `author` (text): Commit author
- `committer` (text): Committer
- `msg` (text): Commit message
- `parents` (text): Parent commit hash
- `author_date` (timestamp): Author commit time
- `committer_date` (timestamp): Committer commit time
- `num_lines_added` (bigint): Number of lines added
- `num_lines_deleted` (bigint): Number of lines deleted
- `merge` (boolean): Whether it is a merge commit
- `dmm_unit_complexity` (double): Code complexity metric
- `dmm_unit_interfacing` (double): Interface complexity metric
- `dmm_unit_size` (double): Code size metric

**Relationships**:
- Related to `fixes` table via `hash` and `repo_url`
- Related to `file_change` table via `hash`

---

### 3. `file_change` - File-Level Code Changes Table
**Record Count**: 103,703  
**Purpose**: Stores file-level code change information, including pre- and post-modification code, diff information, etc.

**Field Descriptions**:
- `file_change_id` (text): Unique identifier for file change
  - **Format**: Numeric string (e.g., "202280460594685", "131461250543157")
  - **Uniqueness**: Each `file_change_id` is unique (103,703 records, 103,703 unique values)
  - **Example Values**: `202280460594685`, `131461250543157`, `147219822889344`
- `hash` (text): Associated commit hash
- `filename` (text): Filename
- `old_path` (text): Old file path
- `new_path` (text): New file path
- `change_type` (text): Change type (ADD, MODIFY, DELETE, etc.)
- `diff` (text): Git diff raw content
- `diff_parsed` (text): Parsed diff information
- `code_before` (text): **Pre-fix vulnerable code** (important field)
- `code_after` (text): **Post-fix code** (important field)
- `programming_language` (text): Programming language (e.g., "Java", "Go", "Python", etc.)
- `num_lines_added` (integer): Number of lines added
- `num_lines_deleted` (integer): Number of lines deleted
- `nloc` (text): Number of lines of code
- `complexity` (text): Code complexity
  - **Data Type**: Text type, but stores numeric values or special values
  - **Value Range**: 
    - **Special Values**:
      - `nan` (24,483 records, 23.61%): Indicates complexity cannot be calculated (usually non-code files like Markdown, Shell scripts, etc.)
      - `None` (3,202 records, 3.09%): NULL value
    - **Numeric Types**:
      - **Decimal Form** (61,920 records): e.g., `0.0`, `1.0`, `2.0`, `9.0`, `32.0`, `64.0`, `412.0`, `456.0`, etc.
      - **Integer Form** (14,098 records): e.g., `0`, `1`, `2`, `3`, `12`, `92`, `126`, etc.
      - **Large Values**: Range from `0` to `87232.0`, common range is 0-500
  - **Common Values**: 
    - `0.0` (6,137 records, 5.92%)
    - `1.0` (1,655 records, 1.60%)
    - `2.0` (1,619 records, 1.56%)
    - `0` (1,530 records, 1.48%)
    - `4.0` (1,322 records, 1.27%)
    - `3.0` (1,266 records, 1.22%)
  - **Note**: Higher complexity values indicate more complex code. Values of `nan` or `None` usually indicate the file cannot be analyzed for complexity (e.g., configuration files, documentation, etc.)
- `token_count` (text): Token count

**Relationships**:
- Related to `commits` table via `hash`
- Related to `method_change` table via `file_change_id`

**Usage**: This is the main data source for extracting vulnerability code patterns. The `code_before` field contains vulnerable code, and the `code_after` field contains fixed code.

---

### 4. `method_change` - Method-Level Code Changes Table
**Record Count**: 229,511  
**Purpose**: Stores method-level code change information, providing finer-grained code analysis.

**Field Descriptions**:
- `method_change_id` (text): Unique identifier for method change
- `file_change_id` (text): Associated file change ID
- `name` (text): Method name
- `signature` (text): **Method signature** (important field, used for pattern matching)
- `parameters` (text): Method parameters
- `start_line` (text): Start line number
- `end_line` (text): End line number
- `code` (text): Method code content
- `before_change` (text): Pre-change code
- `nloc` (text): Number of lines of code
- `complexity` (text): Code complexity
- `token_count` (text): Token count
- `top_nesting_level` (text): Maximum nesting level

**Relationships**:
- Related to `file_change` table via `file_change_id`

**Usage**: Used for recurring vulnerability pattern identification based on method signatures.

---

### 5. `cve` - CVE Vulnerability Information Table
**Record Count**: 249,380  
**Purpose**: Stores detailed CVE (Common Vulnerabilities and Exposures) information, including vulnerability descriptions, severity, CVSS scores, etc.

**Field Descriptions**:
- `cve_id` (text): CVE ID (primary key)
- `published_date` (text): Publication date
- `last_modified_date` (text): Last modification date
- `description` (text): Vulnerability description
- `severity` (text): Severity (LOW, MEDIUM, HIGH, CRITICAL)
- `cvss2_base_score` (text): CVSS v2 base score
- `cvss3_base_score` (text): CVSS v3 base score
- `cvss3_base_severity` (text): CVSS v3 severity
- `cvss2_vector_string` (text): CVSS v2 vector string
- `cvss3_vector_string` (text): CVSS v3 vector string
- `cvss2_access_vector` (text): CVSS v2 attack vector
- `cvss3_attack_vector` (text): CVSS v3 attack vector
- `cvss2_access_complexity` (text): CVSS v2 attack complexity
- `cvss3_attack_complexity` (text): CVSS v3 attack complexity
- `obtain_all_privilege` (text): Whether all privileges can be obtained
- `obtain_user_privilege` (text): Whether user privileges can be obtained
- `user_interaction_required` (text): Whether user interaction is required
- `reference_json` (text): Reference links (JSON format)
- `problemtype_json` (text): Problem type (JSON format)
- `nodes` (text): CVE node information (JSON format)

**Data Example**:
```
CVE-1999-0001 | 1999-12-30T05:00Z | MEDIUM | nan
```

**Relationships**:
- Related to `fixes` table via `cve_id`
- Related to `cwe_classification` table via `cve_id`
- Related to `cve_cpe_mapper` table via `cve_id`
- Related to `cve_project` table via `cve` field

---

### 6. `cwe` - CWE Weakness Type Definitions Table
**Record Count**: 1,376  
**Purpose**: Stores CWE (Common Weakness Enumeration) weakness type definition information.

**Field Descriptions**:
- `index` (bigint): Index
- `cwe_id` (text): CWE ID (e.g., "CWE-79")
- `cwe_name` (text): CWE name (e.g., "Cross-site Scripting (XSS)")
- `description` (text): CWE description
- `extended_description` (text): Extended description
- `url` (text): CWE official link
- `is_category` (boolean): Whether it is a category

**Relationships**:
- Related to `cwe_classification` table via `cwe_id`

---

### 7. `cwe_classification` - CVE-CWE Classification Mapping Table
**Record Count**: 253,162  
**Purpose**: Establishes mapping relationships between CVE and CWE. One CVE may correspond to multiple CWEs.

**Field Descriptions**:
- `cve_id` (text): CVE ID
- `cwe_id` (text): CWE ID

**Relationships**:
- Related to `cve` table via `cve_id`
- Related to `cwe` table via `cwe_id`

**Usage**: Used to obtain weakness type classifications for vulnerabilities, helping understand the nature of vulnerabilities.

---

### 8. `cve_cpe_mapper` - CVE-CPE Mapping Table
**Record Count**: 343,949  
**Purpose**: Establishes mapping relationships between CVE and CPE (Common Platform Enumeration), used to identify affected software products.

**Field Descriptions**:
- `id` (integer): Primary key (auto-increment)
- `cve_id` (varchar): CVE ID
- `cpe_name` (text): CPE name (e.g., "cpe:2.3:a:apache:struts:2.3.0:*:*:*:*:*:*:*")

**Relationships**:
- Related to `cve` table via `cve_id`
- Related to `cpe_project` table via `cpe_name`

---

### 9. `cve_project` - CVE-Project Association Table
**Record Count**: 92,467  
**Purpose**: Establishes association relationships between CVE and projects (GitHub repositories).

**Field Descriptions**:
- `id` (integer): Primary key (auto-increment)
- `cve` (varchar): CVE ID
- `project_url` (varchar): Project URL (usually GitHub repository URL)
- `rel_type` (varchar): Relationship type
- `` (varchar): Whether checked, defaults to 'False'

**Relationships**:
- Related to `cve` table via `cve`
- Related to `repository` table via `project_url`

---

### 10. `cpe_project` - CPE-Project Association Table
**Record Count**: 11,883  
**Purpose**: Establishes association relationships between CPE and projects.

**Field Descriptions**:
- `cpe_name` (varchar): CPE name
- `repo_url` (varchar): Repository URL
- `rel_type` (varchar): Relationship type

**Relationships**:
- Related to `cve_cpe_mapper` table via `cpe_name`
- Related to `repository` table via `repo_url`

---

### 11. `repository` - Code Repository Information Table
**Record Count**: 7,238  
**Purpose**: Stores metadata information for code repositories (mainly GitHub repositories).

**Field Descriptions**:
- `repo_url` (text): Repository URL (primary key)
- `repo_name` (text): Repository name
- `description` (text): Repository description
- `date_created` (timestamp): Creation date
- `date_last_push` (timestamp): Last push date
- `homepage` (text): Homepage URL
- `repo_language` (text): Primary programming language
- `owner` (text): Repository owner
- `forks_count` (bigint): Fork count
- `stars_count` (bigint): Star count

**Relationships**:
- Related to `commits` table via `repo_url`
- Related to `fixes` table via `repo_url`
- Related to `cve_project` table via `project_url`

---

### 12. `users` - User Table
**Record Count**: 0  
**Purpose**: Stores system user information (currently an empty table).

**Field Descriptions**:
- `id` (varchar): User ID (primary key)
- `hashed_password` (varchar): Hashed password
- `firstname` (varchar): First name
- `lastname` (varchar): Last name
- `photo` (varchar): Photo
- `account_created` (varchar): Account creation time
- `last_access` (varchar): Last access time

---

## Data Relationship Diagram

```
cve (CVE Information)
  ├── fixes (Fix Records) ──> commits (Commit Records) ──> file_change (File Changes) ──> method_change (Method Changes)
  ├── cwe_classification (CWE Classification) ──> cwe (CWE Definitions)
  ├── cve_cpe_mapper (CPE Mapping) ──> cpe_project (CPE-Project Associations) ──> repository (Repository Information)
  └── cve_project (CVE-Project Associations) ──> repository (Repository Information)
```

## rel_type Field Explanation

The `rel_type` field appears in multiple tables (`fixes`, `cve_project`, `cpe_project`) and is used to identify how CVEs are associated with code repositories/commits. Different relationship types represent different data sources and matching methods.

### rel_type in fixes Table (8 Types)

| rel_type | Record Count | Description |
|----------|--------------|-------------|
| **CPE_GIT_REPOBASED** | 260,185 | Matched to Git repository via CPE (Common Platform Enumeration), repository-level association |
| **NVD_GIT_REPOBASED** | 90,995 | Matched to Git repository via NVD (National Vulnerability Database), repository-level association |
| **CPE_DIRECT_COMMIT** | 42,291 | Directly matched to specific Git commit via CPE |
| **GHSD_GIT_REPOBASED** | 21,781 | Matched to Git repository via GHSD (GitHub Security Advisory), repository-level association |
| **CPE_GITHUB_SEARCH** | 18,993 | Matched repository via CPE search on GitHub |
| **NVD_DIRECT_COMMIT** | 15,714 | Directly matched to specific Git commit via NVD |
| **GHSD_REGISTRY** | 9,876 | Matched project via GHSD in registry |
| **GHSD_DIRECT_COMMIT** | 4,461 | Directly matched to specific Git commit via GHSD |

**Total**: 464,296 records

### rel_type in cve_project Table (7 Types)

| rel_type | Record Count | Description |
|----------|--------------|-------------|
| **CPE_GIT_REPOBASED** | 52,837 | CPE association with Git repository |
| **NVD_GIT_REPOBASED** | 19,073 | NVD association with Git repository |
| **CPE_DIRECT_COMMIT** | 10,780 | CPE association with direct commit |
| **CPE_GITHUB_SEARCH** | 4,435 | CPE association via GitHub search |
| **GHSD_GIT_REPOBASED** | 3,665 | GHSD association with Git repository |
| **GHSD_REGISTRY** | 1,676 | GHSD association with registry |
| **NVD_REGISTRY** | 1 | NVD association with registry |

**Total**: 92,467 records

### rel_type in cpe_project Table (3 Types)

| rel_type | Record Count | Description |
|----------|--------------|-------------|
| **GIT_REPOBASED** | 10,328 | Git repository-based association |
| **GITHUB_SEARCH** | 1,189 | Association via GitHub search |
| **DIRECT_COMMIT** | 366 | Direct commit association |

**Total**: 11,883 records

### Relationship Type Meaning Explanation

- **REPOBASED**: Repository-level association, indicates CVE is related to the entire code repository
- **DIRECT_COMMIT**: Directly associated with specific commit, indicates the specific commit fixing the vulnerability was found
- **GITHUB_SEARCH**: Association found via GitHub search functionality
- **REGISTRY**: Association found via software package registries (e.g., npm, PyPI)

### Data Source Explanation

- **CPE**: Common Platform Enumeration, used to identify software products
- **NVD**: National Vulnerability Database, U.S. National Vulnerability Database
- **GHSD**: GitHub Security Advisory, GitHub security advisories

### Usage Recommendations

1. **REPOBASED** type: Suitable for analyzing vulnerability fix patterns across entire projects
2. **DIRECT_COMMIT** type: Suitable for precise analysis of fix code for specific vulnerabilities
3. **GITHUB_SEARCH** type: May contain some indirect associations, requires additional verification when using
4. When querying, filter by `rel_type` to select more reliable data sources

## Typical Query Workflows

### 1. Extract Vulnerability Code Patterns (e.g., extract_recurring_vulnerabilities.py)

```sql
SELECT 
    f.cve_id,
    f.hash as commit_hash,
    f.repo_url,
    fc.file_change_id,
    fc.filename,
    fc.programming_language,
    fc.code_before as vulnerable_code,
    fc.code_after as fixed_code,
    mc.method_signature,
    mc.code as method_code
FROM fixes f
JOIN commits c ON f.hash = c.hash
JOIN file_change fc ON c.hash = fc.hash
LEFT JOIN method_change mc ON fc.file_change_id = mc.file_change_id
WHERE fc.programming_language IN ('Java', 'Go')
    AND fc.code_before IS NOT NULL
    AND f.score >= 65
```

### 2. Get CVE's CWE Classification

```sql
SELECT 
    cc.cve_id,
    cc.cwe_id,
    c.cwe_name,
    c.description as cwe_description
FROM cwe_classification cc
JOIN cwe c ON cc.cwe_id = c.cwe_id
WHERE cc.cve_id = 'CVE-2020-28620'
```

## Notes

1. **Data Volume**: The `fixes` table is the largest table (460,000+ records), pay attention to performance optimization when querying
2. **Code Fields**: The `file_change.code_before` and `file_change.code_after` fields may contain large amounts of text, pay attention to memory usage when querying
3. **Join Queries**: When joining multiple tables, pay attention to index usage. Main indexes are on fields like `cve_id`, `hash`, `repo_url`
4. **NULL Handling**: Some fields may be NULL, handle appropriately when querying
5. **Programming Language**: The `file_change.programming_language` field is used to filter code for specific languages

## References

- MoreFixes Paper: https://dl.acm.org/doi/abs/10.1145/3663533.3664036
- CVE Database: https://cve.mitre.org/
- CWE Database: https://cwe.mitre.org/
- CPE Specification: https://nvd.nist.gov/products/cpe
