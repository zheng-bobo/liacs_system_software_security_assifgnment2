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

2. **模式识别**：使用多层次代码相似性匹配识别重复漏洞模式
   - 代码标准化（空白字符、变量名归一化）
   - Token Shingles 生成（用于文本相似度匹配）
   - AST 解析与哈希（结构相似度匹配）
   - 关键字提取
   - 多特征相似度计算与聚类

3. **查询生成**：为每个识别出的模式生成 GitHub 搜索查询
   - 基础关键字搜索
   - TF-IDF 优化的查询
   - 正则表达式模式查询
   - 路径过滤查询

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

复制 `env.sample` 文件并配置数据库连接信息：

```bash
cp env.sample .env
```

编辑 `.env` 文件，设置以下变量：

```env
POSTGRES_USER=your_username
POSTGRES_PASSWORD=your_password
DB_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=morefixes
```

## 🎯 快速开始

### 基本使用

```bash
python vulnerability_pattern_miner.py --top-n 3 --min-score 65 --languages java
```

### 命令行参数

- `--top-n`: 返回出现次数最多的前 n 个模式（默认: 3）
- `--min-score`: fixes.score 的最小值（默认: 65）
- `--include-merge`: 包含 merge commit（默认: 排除）
- `--languages`: 编程语言列表，不区分大小写（默认: java）

### 示例

```bash
# 提取前 5 个最常见的 Java 漏洞模式
python detect_recurring_vulnerabilities.py --top-n 5 --languages java

# 提取 Go 语言的漏洞模式
python detect_recurring_vulnerabilities.py --top-n 3 --languages go

# 提取多个语言的漏洞模式
python detect_recurring_vulnerabilities.py --top-n 3 --languages java python go
```

## 📊 工作流程

### Step 1: 数据提取

从数据库中提取高质量的漏洞修复样本。

**筛选条件**：
- `fixes.score >= 65`（高质量修复样本，准确率约 95%+）
- `file_change.diff IS NOT NULL`（要求有代码差异）
- `commits.merge = FALSE`（排除 merge commit，默认）
- `file_change.programming_language`（支持多语言，默认 Java）

**提取字段**：
- `cve_id`: CVE 编号
- `hash`: Commit hash
- `repo_url`: 仓库 URL
- `filename`: 文件名
- `code_before`: 漏洞前的代码
- `code_after`: 修复后的代码
- `diff`: 代码差异

**输出**: `output/extract_java_vulnerable_code.csv`

### Step 2: 代码标准化与相似性匹配

使用 `CodeSimilarityMatcher` 对每个漏洞代码进行多层次标准化处理：

1. **原始代码（Raw Text）**：保留原始代码，用于对照和人工检查
2. **空白字符标准化**：去除缩进、统一空格，提高文本一致性
3. **变量名标准化**：将变量名、方法名、类名替换为统一占位符（VAR_x, FUNC_x, CLASS_x）
4. **Token Shingles**：将代码切分成 token，生成固定长度的 shingles（默认 5 个 token）
5. **AST 解析与哈希**：使用 AST parser 生成结构哈希，用于结构相似度匹配
6. **关键字提取**：提取关键函数、API、库名等

### Step 3: 模式识别与聚类

结合多种特征进行漏洞模式聚类：
- Token Shingles (MinHash/LSH): 文本相似性
- AST subtree hash: 结构语义匹配
- Keyword tokens: 初步分组
- Normalized text: 人工验证

**输出**: `output/pattern_records_top{n}.csv` 和 `output/similar_fixes_top{n}.csv`

### Step 4: GitHub 查询生成

为每个识别出的模式生成多条 GitHub 搜索查询：

1. **基础关键字搜索**：使用模式中的关键函数和 API
2. **TF-IDF 优化的查询**：提取中频危险 tokens
3. **正则表达式模式查询**：基于标准化代码生成
4. **路径过滤查询**：结合文件扩展名过滤

**输出**: `output/github_queries.csv`

## 📁 模块结构

```
Morefixes/
├── vulnerability_pattern_miner.py       # 主程序入口
├── code_similarity_matcher.py          # 代码相似性匹配模块
├── github_query_generator.py           # GitHub 查询生成模块
├── DATABASE_TABLES_EXPLANATION.md      # 数据库表结构说明
├── VULNERABILITY_PATTERN_MINING.md     # 漏洞模式挖掘流程文档
├── SIMILARITY_MATCHER_README.md        # 相似性匹配器文档
└── output/                             # 输出目录
    ├── extract_java_vulnerable_code.csv
    ├── pattern_records_top{n}.csv
    ├── similar_fixes_top{n}.csv
    └── github_queries.csv
```

### 主要模块说明

#### `vulnerability_pattern_miner.py`
主程序文件，包含：
- `DatabaseConnector`: 数据库连接器
- `extract_java_vulnerable_code()`: 从数据库提取漏洞代码
- `process_recurring_patterns()`: 识别重复模式
- `main()`: 主函数，协调整个流程

#### `code_similarity_matcher.py`
代码相似性匹配模块，包含：
- `CodeSimilarityMatcher`: 多层次代码相似性匹配类
- 支持多种代码表示方法（Raw、Whitespace-normalized、Identifier-normalized、Token Shingles、AST Hash）
- 多种相似度计算方法（Jaccard、Exact、AST Hash、Combined）

#### `github_query_generator.py`
GitHub 查询生成模块，包含：
- `GitHubQueryGenerator`: GitHub 查询生成器类
- `extract_tfidf_dangerous_tokens()`: 提取 TF-IDF 中频危险 tokens
- `generate_github_queries()`: 生成多种类型的 GitHub 查询

## 💻 使用方法

### Python API

```python
from vulnerability_pattern_miner import (
    DatabaseConnector,
    extract_java_vulnerable_code,
    process_recurring_patterns,
    main
)
from github_query_generator import GitHubQueryGenerator

# 初始化数据库连接
db_connector = DatabaseConnector()

# 提取漏洞代码
vulnerable_code_df = extract_java_vulnerable_code(
    db_connector,
    min_score=65,
    exclude_merge_commits=True,
    programming_languages=["Java"],
    require_diff=True
)

# 识别重复模式
pattern_records_df = process_recurring_patterns(
    vulnerable_code_df,
    top_n=3,
    similarity_method="combined",
    similarity_threshold=0.5
)

# 生成 GitHub 查询
if len(pattern_records_df) > 0:
    query_generator = GitHubQueryGenerator()
    github_queries_df = query_generator.generate_github_queries(
        pattern_records_df,
        output_dir=Path("output")
    )
```

### 使用 CodeSimilarityMatcher

```python
from code_similarity_matcher import CodeSimilarityMatcher

# 创建匹配器
matcher = CodeSimilarityMatcher(shingle_size=5, use_ast=True)

# 计算代码的所有表示
code = "public class Test { ... }"
representations = matcher.compute_all_representations(code, language="java")

# 计算两个代码的相似度
similarity = matcher.compute_similarity(repr1, repr2, method="combined")

# 从 DataFrame 中找出相似的修复
similar_fixes_df, pattern_records_df = matcher.find_similar_fixes(
    df,
    top_n=10,
    similarity_threshold=0.5,
    similarity_method="combined",
    use_keyword_grouping=True,
    create_patterns=True
)
```

## 📤 输出结果

### Pattern Records (`pattern_records_top{n}.csv`)

包含以下字段：
- `pattern_id`: 模式 ID（如 p001）
- `language`: 编程语言
- `normalized_pattern_text`: 标准化模式文本
- `keyword_tokens`: 关键字 tokens 列表
- `regex`: 正则表达式模式
- `ast_hash`: AST 哈希值
- `example_cves`: 示例 CVE 列表
- `example_snippet`: 示例代码片段
- `pattern_count`: 该模式出现的次数

### Similar Fixes (`similar_fixes_top{n}.csv`)

包含以下字段：
- `similarity`: 相似度分数 (0-1)
- `fix1_hash`, `fix2_hash`: 两个修复的 commit hash
- `fix1_cve`, `fix2_cve`: 两个修复对应的 CVE ID
- `fix1_repo`, `fix2_repo`: 两个修复的仓库 URL
- `fix1_code_before`, `fix1_code_after`: 第一个修复的代码（修复前后）
- `fix2_code_before`, `fix2_code_after`: 第二个修复的代码（修复前后）

### GitHub Queries (`github_queries.csv`)

包含以下字段：
- `pattern_id`: 模式 ID
- `query_id`: 查询 ID（每个模式有多个查询）
- `query_type`: 查询类型（keyword_basic, tfidf_refined, regex_based, path_filter）
- `github_query`: GitHub 搜索查询语句
- `description`: 查询描述

## 📚 相关文档

- [DATABASE_TABLES_EXPLANATION.md](DATABASE_TABLES_EXPLANATION.md): 数据库表结构详细说明
- [VULNERABILITY_PATTERN_MINING.md](VULNERABILITY_PATTERN_MINING.md): 漏洞模式挖掘完整流程文档
- [SIMILARITY_MATCHER_README.md](SIMILARITY_MATCHER_README.md): 代码相似性匹配器详细文档

## 🔧 配置说明

### 相似度计算方法

- `jaccard`: 基于 token shingles 的 Jaccard 相似度（默认）
- `exact`: 精确匹配（比较 normalized_text）
- `ast_hash`: AST 结构相似度
- `combined`: 综合多特征相似度（推荐）

### 相似度阈值

- 默认值: `0.5`
- 建议范围: `0.4 - 0.7`
- 过低会产生太多误报，过高会漏掉相似项

### 性能优化

- 使用 `use_keyword_grouping=True` 进行预分组以提高效率
- 对于大量数据，建议使用 `limit` 参数限制处理数量
- 相似度计算是 O(n²) 复杂度，注意数据规模

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
  识别出的重复模式数: 3
  生成的 GitHub 查询数: 12
============================================================
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

详见 [LICENSE.txt](LICENSE.txt)
