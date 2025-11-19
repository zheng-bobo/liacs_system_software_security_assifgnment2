# 检测重复出现的漏洞代码模式

从 MoreFixes 数据库中提取漏洞代码，识别重复出现的漏洞模式，并生成 GitHub 搜索查询。

## 📋 目录

- [功能特性](#功能特性)
- [安装和配置](#安装和配置)
- [快速开始](#快速开始)
- [工作流程](#工作流程)
- [模块结构](#模块结构)
- [使用方法](#使用方法)
- [输出结果](#输出结果)
- [相关文档](#相关文档)

## ✨ 功能特性

1. **数据提取**：从 MoreFixes 数据库中提取高质量的漏洞修复样本
   - 支持多编程语言（默认 Java）
   - 可配置的质量阈值（score >= 65，准确率约 95%+）
   - 自动排除 merge commits
   - 支持按 CWE 类型筛选（Top N CWE）

2. **模式识别**：使用 source/sink/taint 分析识别重复漏洞模式
   - Source 识别：识别不可信输入源（如 `getParameter`, `getHeader` 等）
   - Sink 识别：识别危险使用点（如 SQL 执行、XSS 输出、路径操作等）
   - Taint 流分析：追踪数据从 source 到 sink 的传播路径
   - 安全措施分析：识别缺失的安全措施（如 HTML 转义、路径规范化等）
   - 支持特定 CWE 类型的针对性分析（CWE-79 XSS、CWE-22 Path Traversal 等）

3. **查询生成**：为每个识别出的模式生成 GitHub 搜索查询
   - 基于 source/sink 关键词生成查询
   - 根据 CWE 类型优化查询关键词
   - 支持调用 GitHub API 进行实际搜索
   - 自动处理 GitHub API rate limit

## 🚀 安装和配置

### 环境要求

- Python 3.8+
- PostgreSQL 数据库（MoreFixes 数据库）
- 相关 Python 包（见 `requirements.txt`）

### 安装依赖

```bash
pip install -r requirements.txt
```

### 配置环境变量

创建 `.env` 文件并配置数据库连接信息：

```bash
# 在项目根目录创建 .env 文件
touch .env
```

编辑 `.env` 文件，设置以下变量：

```env
# 数据库配置
POSTGRES_USER=your_username
POSTGRES_PASSWORD=your_password
DB_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=morefixes

# GitHub API 配置（可选，但建议设置以提高 rate limit）
GITHUB_TOKEN=your_github_personal_access_token
```

**注意**: `.env` 文件包含敏感信息，请确保已添加到 `.gitignore` 中，不要提交到版本控制系统。

### GitHub Token 获取

如果需要使用 GitHub API 搜索功能，需要创建 GitHub Personal Access Token：

1. 访问 https://github.com/settings/tokens
2. 点击 "Generate new token (classic)"
3. 选择权限：至少需要 `public_repo` 权限
4. 复制生成的 token 并添加到 `.env` 文件

## 🎯 快速开始

### 基本使用

```bash
python vulnerability_pattern_miner.py --top-n 3 --min-score 65 --languages java
```

### 命令行参数

- `--top-n`: 返回出现次数最多的前 n 个 CWE 类型（默认: 3）
- `--min-score`: fixes.score 的最小值（默认: 65）
- `--include-merge`: 包含 merge commit（默认: 排除）
- `--languages`: 编程语言列表，不区分大小写（默认: java）

### 示例

```bash
# 提取前 3 个最常见的 Java 漏洞模式（CWE-79, CWE-22 等）
python vulnerability_pattern_miner.py --top-n 3 --languages java

# 提取前 5 个最常见的漏洞模式
python vulnerability_pattern_miner.py --top-n 5 --languages java

# 提取多个语言的漏洞模式
python vulnerability_pattern_miner.py --top-n 3 --languages java python go
```

## 📊 工作流程

### Step 1: 数据提取

从数据库中提取高质量的漏洞修复样本。

**筛选条件**：
- `fixes.score >= 65`（高质量修复样本，准确率约 95%+）
- `file_change.diff IS NOT NULL`（要求有代码差异）
- `commits.merge = FALSE`（排除 merge commit，默认）
- `file_change.programming_language`（支持多语言，默认 Java）
- 只包含单文件变更的修复（`file_change_count = 1`）

**提取字段**：
- `cve_id`: CVE 编号
- `hash`: Commit hash
- `repo_url`: 仓库 URL
- `filename`: 文件名
- `code_before`: 漏洞前的代码
- `code_after`: 修复后的代码
- `diff`: 代码差异

**输出**: `output/extract_java_vulnerable_code.csv`

### Step 2: CWE 分类与模式识别

1. **CWE 分类统计**：统计每个 CWE 类型的 CVE 数量，选出 Top N
2. **方法级代码提取**：从每个 CVE 中提取方法级代码变更
3. **Source/Sink/Taint 分析**：
   - 识别不可信输入源（Source）
   - 识别危险使用点（Sink）
   - 追踪数据流（Taint Flow）
   - 分析缺失的安全措施
4. **模式过滤**：根据 CWE 类型调整过滤条件
   - CWE-79 (XSS) 和 CWE-22 (Path Traversal): 需要完整的 source → sink → taint flow
   - NVD-CWE-noinfo: 放宽条件，只需 source 和 sink

**输出**: `output/cwe_based_patterns_top{n}.csv` 和 `output/top_cwe_top{n}.csv`

### Step 3: GitHub 查询生成

为每个识别出的模式生成 GitHub 搜索查询：

1. **查询生成**：基于 source/sink 关键词生成查询字符串
2. **CWE 类型优化**：根据 CWE 类型优化关键词选择
3. **文件保存**：自动保存包含查询的 DataFrame

**输出**: `output/cwe_based_patterns_top{n}.csv`（包含 `github_query` 列）

### Step 4: GitHub API 搜索（可选）

调用 GitHub API 进行实际搜索：

1. **批量搜索**：遍历所有生成的查询
2. **结果提取**：提取仓库、文件路径、URL 等信息
3. **Rate Limit 处理**：自动处理 API 限制
4. **结果保存**：保存搜索结果到文件

**输出**: `output/github_search_results.csv`

## 📁 模块结构

```
liacs_system_software_security/
├── vulnerability_pattern_miner.py       # 主程序入口
├── github_query_generator.py             # GitHub 查询生成和 API 调用模块
├── DATABASE_TABLES_EXPLANATION.md       # 数据库表结构说明
├── VULNERABILITY_PATTERN_MINING.md      # 漏洞模式挖掘流程文档
├── requirements.txt                     # Python 依赖包列表
├── docker-compose.yml                   # Docker 配置（可选）
└── output/                              # 输出目录
    ├── extract_java_vulnerable_code.csv
    ├── top_cwe_top{n}.csv
    ├── cwe_based_patterns_top{n}.csv
    └── github_search_results.csv        # GitHub API 搜索结果（可选）
```

### 主要模块说明

#### `vulnerability_pattern_miner.py`
主程序文件，包含：
- `DatabaseConnector`: 数据库连接器
- `extract_java_vulnerable_code()`: 从数据库提取漏洞代码（支持 Top N CWE 筛选）
- `process_cwe_based_patterns()`: 基于 CWE 的模式识别
- `extract_vulnerability_pattern()`: 提取漏洞模式（source/sink/taint 分析）
- `analyze_source_sink_taint()`: 分析 source、sink 和 taint 流
- `analyze_missing_security()`: 分析缺失的安全措施
- `main()`: 主函数，协调整个流程

#### `github_query_generator.py`
GitHub 查询生成和 API 调用模块，包含：
- `GitHubQueryGenerator`: GitHub 查询生成器类
- `generate_github_search_keywords()`: 为 DataFrame 生成 GitHub 查询并保存文件
- `search_github_code()`: 使用 GitHub API 搜索代码
- `search_github_with_queries()`: 批量调用 GitHub API 搜索
- `_make_github_request()`: 底层 API 请求处理（含 rate limit 处理）

## 💻 使用方法

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

# 初始化数据库连接
db_connector = DatabaseConnector()

# 提取漏洞代码（包含 Top N CWE 筛选）
vulnerable_code_df = extract_java_vulnerable_code(
    db_connector,
    min_score=65,
    exclude_merge_commits=True,
    programming_languages=["Java"],
    require_diff=True,
    top_n=3,  # 只提取 Top 3 CWE 的数据
    output_dir=Path("output")
)

# 识别重复模式（基于 CWE）
recurring_patterns_df = process_cwe_based_patterns(
    vulnerable_code_df,
    db_connector,
    top_n=3,
    min_score=65,
    programming_languages=["Java"],
    output_dir=Path("output")
)

# 生成 GitHub 查询
query_generator = GitHubQueryGenerator()
recurring_patterns_df = query_generator.generate_github_search_keywords(
    recurring_patterns_df,
    output_dir=Path("output"),
    top_n=3,
    save_file=True
)

# 调用 GitHub API 搜索（可选）
if len(recurring_patterns_df) > 0:
    results_df = query_generator.search_github_with_queries(
        recurring_patterns_df,
        language="java",
        max_results_per_query=100,
        save_results=True,
        output_dir="output"
    )
```

### 直接运行主程序

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

## 📤 输出结果

### 原始数据 (`extract_java_vulnerable_code.csv`)

包含以下字段：
- `cve_id`: CVE 编号
- `hash`: Commit hash
- `repo_url`: 仓库 URL
- `filename`: 文件名
- `score`: 修复质量分数
- `programming_language`: 编程语言
- `diff`: 代码差异

### Top CWE 列表 (`top_cwe_top{n}.csv`)

包含以下字段：
- `cwe_id`: CWE 编号
- `cwe_name`: CWE 名称
- `fix_count`: 该 CWE 的修复数量

### 模式记录 (`cwe_based_patterns_top{n}.csv`)

包含以下字段：
- `cwe_id`: CWE 编号
- `cwe_name`: CWE 名称
- `cve_id`: CVE 编号
- `file_change_id`: 文件变更 ID
- `method_change_id`: 方法变更 ID
- `method_name`: 方法名
- `signature`: 方法签名
- `sources`: Source 列表（JSON 字符串）
- `sinks`: Sink 列表（JSON 字符串）
- `taint_flows`: Taint 流列表（JSON 字符串）
- `tainted_variables`: 被污染的变量列表（JSON 字符串）
- `missing_sanitizers`: 缺失的 sanitizer 列表（JSON 字符串）
- `added_security_measures`: 新增的安全措施列表（JSON 字符串）
- `github_query`: GitHub 搜索查询字符串
- `method_code`: 方法代码（前 500 字符）

### GitHub 搜索结果 (`github_search_results.csv`)

如果调用了 GitHub API，会生成此文件，包含：
- 所有模式记录的字段
- `github_search_results`: 搜索结果列表（JSON 字符串）
- `github_result_count`: 结果数量

每个搜索结果包含：
- `repository`: 仓库全名（如 `owner/repo`）
- `repository_url`: 仓库 URL
- `path`: 文件路径
- `url`: API URL
- `html_url`: GitHub 网页 URL
- `sha`: 文件 SHA

## 🔧 配置说明

### CWE 类型支持

当前支持以下 CWE 类型的针对性分析：

- **CWE-79**: Cross-site Scripting (XSS)
  - 重点关注 XSS sinks（println, print, innerHTML 等）
  - 检查 HTML 转义安全措施

- **CWE-22**: Path Traversal
  - 重点关注文件操作 sinks（new File, Files.readAllBytes 等）
  - 检查路径规范化安全措施

- **NVD-CWE-noinfo**: Insufficient Information
  - 使用通用模式匹配
  - 放宽过滤条件

### GitHub API Rate Limit

- **未认证**: 60 请求/小时
- **已认证**: 5000 请求/小时（需要设置 `GITHUB_TOKEN`）

程序会自动处理 rate limit，当达到限制时会等待重置。

### 性能优化

- 使用 `top_n` 参数限制处理的 CWE 数量
- 对于大量数据，建议先测试小规模数据
- GitHub API 搜索可能需要较长时间，建议在后台运行

## 📝 示例输出

运行程序后，会在控制台输出统计信息：

```
============================================================
统计信息:
  总记录数: 1234
  唯一 CVE 数: 567
  唯一 commit 数: 890
  唯一仓库数: 234
  唯一文件数: 456
  识别出的重复模式数: 45
  生成的 GitHub 查询数: 45
============================================================
```

## 📚 相关文档

- [DATABASE_TABLES_EXPLANATION.md](DATABASE_TABLES_EXPLANATION.md): 数据库表结构详细说明
- [VULNERABILITY_PATTERN_MINING.md](VULNERABILITY_PATTERN_MINING.md): 漏洞模式挖掘完整流程文档

## 🔍 支持的 CWE 类型

当前主要支持以下 Top 3 CWE 类型：

1. **CWE-79**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
2. **NVD-CWE-noinfo**: Insufficient Information
3. **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## ⚠️ 注意事项

1. **数据库连接**：确保数据库连接配置正确，且数据库可访问
2. **GitHub Token**：如果使用 GitHub API，建议设置 token 以提高 rate limit
3. **数据量**：处理大量数据时可能需要较长时间，建议先测试小规模数据
4. **API 限制**：GitHub API 有 rate limit，程序会自动处理，但可能需要等待
