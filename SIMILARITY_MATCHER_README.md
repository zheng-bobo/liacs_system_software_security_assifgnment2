# 多层次代码相似性匹配系统

## 概述

`CodeSimilarityMatcher` 是一个多层次代码相似性匹配类，实现了基于 8 种不同代码表示方法的相似性匹配系统，用于识别相似的漏洞修复模式。

**模块位置**: `code_similarity_matcher.py`

## 8 种代码表示方法

### 1. 原始代码（Raw Text）

**方法**: `raw_text`（在 `compute_all_representations()` 中返回）

- **用途**: 保留原始代码，用于对照和人工检查
- **处理**: 直接返回原始代码，不做任何修改
- **应用**: 用于对照和人工检查

### 2. 空白字符标准化（Whitespace Normalization）

**方法**: `extract_whitespace_normalized(code, preserve_newlines=False)`

- **用途**: 去除缩进、统一空格，提高文本一致性
- **处理流程**:
  1. 去除所有行首空白字符
  2. 去除空行
  3. 统一空格：多个连续空格替换为单个空格
  4. 根据 `preserve_newlines` 参数决定是否保留换行符
- **应用**: 忽略格式差异，关注代码结构

### 3. 变量名标准化（Identifier Normalization）

**方法**: `extract_identifier_normalized(code, language)`

- **用途**: 将变量名、方法名、类名替换为统一占位符，使不同项目中结构相同的代码能被识别
- **处理流程**:
  1. 先进行空白字符标准化（保留换行）
  2. 使用 AST parser（Java）或正则表达式进行标识符归一化
  3. 替换规则:
     - 变量名 → `VAR1`, `VAR2`, `VAR3`...
     - 方法名 → `FUNC1`, `FUNC2`, `FUNC3`...
     - 类名 → `CLASS1`, `CLASS2`, `CLASS3`...
     - 数字字面量 → `NUM`
     - 字符串字面量 → `STR`
- **应用**: 使不同项目中变量名不同但结构相同的代码能被识别为同一类

**示例**:
```java
// 原始代码
String urlParam = request.getParameter("url");
File file = new File(path);

// 标准化后
VAR1 = VAR2.getParameter(STR);
VAR3 = new VAR4(VAR5);
```

### 4. Token Shingles（标记片段）

**方法**: `extract_token_shingles(code, language)`

- **用途**: 将代码切分成 token，再组成固定长度（默认 5 个 token）的 "shingles"
- **处理流程**:
  1. 原始代码 → 空白字符标准化
  2. → 变量名标准化（VAR1, VAR2...）
  3. → Token 化（按空白字符和标点符号分割）
  4. → 生成固定长度的 shingles（默认 5 个 token）
- **应用**: 
  - MinHash
  - LSH（局部敏感哈希）
  - 代码相似度比较

**示例**:
```
Tokens: ["VAR1", "=", "VAR2", ".", "getParameter", "(", "STR", ")"]
Shingles (size=5): 
  - "VAR1 = VAR2 . getParameter"
  - "= VAR2 . getParameter ("
  - "VAR2 . getParameter ( STR"
  ...
```

### 5. AST 解析 → AST JSON

**方法**: `extract_ast_json(code, language)`（内部使用 `_ast_to_json()`）

- **用途**: 将代码解析为 AST，并转换为 JSON 格式
- **处理流程**:
  1. 原始代码 → 空白字符标准化（保留换行）
  2. → AST 解析（使用 javalang parser）
  3. → AST 转换为 JSON 字典
  4. → JSON 字符串化（用于生成哈希）
- **应用**: 语义结构分析（不受变量名、格式影响）

**AST JSON 结构**:
```json
{
  "type": "CompilationUnit",
  "package": {...},
  "types": [
    {
      "type": "ClassDeclaration",
      "name": "CLASS1",
      "methods": [...]
    }
  ]
}
```

### 6. AST 子树哈希（AST Subtree Hash）

**方法**: `extract_ast_subtree_hash(code, language)`

- **用途**: 用于结构相似性匹配（最稳定的方法）
- **处理流程**:
  1. 原始代码 → 空白字符标准化（保留换行）
  2. → AST 解析 → AST JSON
  3. → JSON 字符串化（`sort_keys=True`）
  4. → SHA256 哈希（取前 16 位）
- **特点**: 
  - 最稳定的匹配方法
  - 不受变量名、格式影响
  - 只关注代码结构
- **应用**: 匹配结构相同但代码写法略不同的模式

### 7. 关键函数 Tokens（Keyword Tokens）

**方法**: `extract_keyword_tokens(code, language)`

- **用途**: 用于基础分组和 GitHub 搜索查询
- **提取内容**:
  - Java 关键字（if, for, while, try, catch, return 等）
  - 方法调用名（如 `getParameter`, `setHeader`）
  - 类名（首字母大写的标识符）
  - 常见 API 调用
- **应用**: 基础分组和 GitHub 查询生成

**示例**:
```java
// 代码
String urlParam = request.getParameter("url");
response.setHeader("Cache-Control", "private");

// 提取的 keywords
{"getParameter", "setHeader", "String", "request", "response", "if", "try"}
```

### 8. 自动生成正则表达式（Regex Pattern）

**方法**: `extract_regex_candidate(code, language)`

- **用途**: 用于精确匹配结构化模式
- **处理流程**:
  1. 先进行变量名标准化
  2. 将 `VAR1`, `VAR2`, `FUNC1` 等替换为 `(\w+)` 通配符
  3. 转义特殊字符，保留通配符
- **应用**: 精确搜索和模式匹配

**示例**:
```
标准化文本: VAR1 = VAR2.getParameter(STR)
正则表达式: (\w+) = (\w+)\.getParameter\((\w+)\)
```

## 使用方法

### 基本使用

```python
from code_similarity_matcher import CodeSimilarityMatcher

# 创建匹配器
matcher = CodeSimilarityMatcher(shingle_size=5, use_ast=True)

# 计算代码的所有表示
code = "public class Test { String url = request.getParameter(\"url\"); }"
representations = matcher.compute_all_representations(code, language="java")

# representations 包含所有8种表示方法：
# - raw_text
# - whitespace_normalized
# - normalized_text
# - token_shingles
# - ast_json
# - ast_subtree_hash
# - keyword_tokens
# - regex_candidate

# 计算两个代码的相似度
similarity = matcher.compute_similarity(repr1, repr2, method="jaccard")
```

### 从 DataFrame 找出相似的修复

```python
from code_similarity_matcher import CodeSimilarityMatcher
import pandas as pd

# 创建匹配器
matcher = CodeSimilarityMatcher(shingle_size=5, use_ast=True)

# 准备数据（包含 code_before, programming_language 等字段）
vulnerable_code_df = pd.DataFrame([...])

# 找出相似的修复模式
similar_fixes_df, pattern_records_df = matcher.find_similar_fixes(
    vulnerable_code_df,
    top_n=10,                    # 返回前10个最相似的
    similarity_threshold=0.5,    # 相似度阈值
    similarity_method="combined", # 相似度计算方法
    use_keyword_grouping=True,   # 使用 keywords 预分组以提高效率
    create_patterns=True,        # 创建模式记录
)
```

### 单独使用各个方法

```python
matcher = CodeSimilarityMatcher(shingle_size=5, use_ast=True)

code = "String url = request.getParameter(\"url\");"

# 空白字符标准化
normalized = matcher.extract_whitespace_normalized(code, preserve_newlines=True)

# 变量名标准化
identifier_normalized = matcher.extract_identifier_normalized(code, language="java")

# Token Shingles
shingles = matcher.extract_token_shingles(code, language="java")

# AST 子树哈希
ast_hash = matcher.extract_ast_subtree_hash(code, language="java")

# 关键字提取
keywords = matcher.extract_keyword_tokens(code, language="java")

# 正则表达式生成
regex = matcher.extract_regex_candidate(code, language="java")
```

## 相似度计算方法

### 1. Jaccard 相似度

**方法**: `method="jaccard"`

- **原理**: 基于 token shingles 的集合交集与并集比例
- **公式**: `similarity = |A ∩ B| / |A ∪ B|`
- **适用**: 一般相似度比较

### 2. 精确匹配

**方法**: `method="exact"`

- **原理**: 比较 normalized_text 文本是否完全相同
- **适用**: 查找完全相同的修复模式（忽略变量名差异）

### 3. AST 哈希匹配

**方法**: `method="ast_hash"`

- **原理**: 比较 AST 子树哈希是否相同
- **适用**: 查找结构相同的修复模式

### 4. 综合多特征相似度（推荐）

**方法**: `method="combined"`

- **原理**: 结合多种特征的加权相似度
- **特征权重**:
  - AST subtree hash: 0.4（最稳定）
  - Token shingles: 0.3（文本近似）
  - Keywords: 0.2（基础分组）
  - Normalized text: 0.1（人工检查）
- **公式**: 
  ```python
  combined_similarity = (
      ast_hash_similarity * 0.4 +
      token_shingles_similarity * 0.3 +
      keywords_similarity * 0.2 +
      normalized_text_similarity * 0.1
  )
  ```
- **适用**: 综合匹配，最准确的方法

## 多特征相似度计算

### compute_multi_feature_similarity()

计算多特征相似度，返回各项相似度和综合相似度：

```python
similarities = matcher.compute_multi_feature_similarity(repr1, repr2)

# 返回字典：
# {
#     "ast_hash": 1.0,
#     "token_shingles": 0.85,
#     "keywords": 0.9,
#     "normalized_text": 1.0,
#     "combined": 0.94
# }
```

## 性能优化

### Keyword 预分组

使用 `use_keyword_grouping=True` 可以大幅减少比较次数：

```python
# 先按 keywords 分组，只在同一组内进行比较
similar_fixes_df, pattern_records_df = matcher.find_similar_fixes(
    df,
    use_keyword_grouping=True,  # 启用预分组
    ...
)
```

### AST Hash 优先

使用 AST hash 作为主要分组键，避免重复计算：

- 在 `find_similar_fixes()` 中，优先使用 `ast_subtree_hash` 进行分组
- 如果没有 AST hash，使用 `normalized_text` 的前 100 字符

## 输出结果

### find_similar_fixes() 返回值

返回两个 DataFrame：

1. **similar_fixes_df**: 相似漏洞对
   - `similarity`: 相似度分数 (0-1)
   - `fix1_hash`, `fix2_hash`: 两个修复的 commit hash
   - `fix1_cve`, `fix2_cve`: 两个修复对应的 CVE ID
   - `fix1_repo`, `fix2_repo`: 两个修复的仓库 URL
   - `fix1_code_before`, `fix1_code_after`: 第一个修复的代码（修复前后）
   - `fix2_code_before`, `fix2_code_after`: 第二个修复的代码（修复前后）

2. **pattern_records_df**: 模式记录
   - `pattern_id`: 模式 ID（如 p001）
   - `language`: 编程语言
   - `normalized_pattern_text`: 标准化模式文本
   - `keyword_tokens`: 关键字 tokens 列表
   - `regex`: 正则表达式模式
   - `ast_hash`: AST 哈希值
   - `example_cves`: 示例 CVE 列表
   - `example_snippet`: 示例代码片段
   - `pattern_count`: 该模式出现的次数

## 依赖要求

### 必需依赖

- `pandas`: 数据处理
- `re`: 正则表达式（Python 内置）
- `hashlib`: 哈希计算（Python 内置）
- `json`: JSON 处理（Python 内置）

### 可选依赖

- `javalang`: Java AST 解析（推荐安装）
  ```bash
  pip install javalang
  ```
  
  如果未安装 `javalang`，会自动回退到正则表达式方法进行标识符标准化。

## 注意事项

1. **性能**: 相似度计算是 O(n²) 复杂度，对于大量数据建议使用 `use_keyword_grouping=True` 进行预分组
2. **阈值**: 根据实际需求调整 `similarity_threshold`，过低会产生太多误报，过高会漏掉相似项
3. **方法选择**: 
   - `jaccard`: 适合一般相似度比较
   - `exact`: 适合查找完全相同的模式
   - `ast_hash`: 适合查找结构相同的模式
   - `combined`: 综合匹配，最准确（推荐）
4. **语言支持**: 
   - Java: 支持 AST 解析（需要 javalang）
   - 其他语言: 使用正则表达式方法进行标识符标准化
5. **内存使用**: 大量数据时注意内存占用，建议分批处理

## 示例

### 示例 1: 基本相似度计算

```python
from code_similarity_matcher import CodeSimilarityMatcher

matcher = CodeSimilarityMatcher(shingle_size=5, use_ast=True)

code1 = "String url = request.getParameter(\"url\");"
code2 = "String path = req.getParameter(\"path\");"

repr1 = matcher.compute_all_representations(code1, language="java")
repr2 = matcher.compute_all_representations(code2, language="java")

# 计算综合相似度
similarities = matcher.compute_multi_feature_similarity(repr1, repr2)
print(f"综合相似度: {similarities['combined']}")
# 输出: 综合相似度: 0.95（结构相同，只是变量名不同）
```

### 示例 2: 从 DataFrame 查找相似模式

```python
import pandas as pd
from code_similarity_matcher import CodeSimilarityMatcher

# 准备数据
df = pd.DataFrame({
    'code_before': [
        "String url = request.getParameter(\"url\");",
        "String path = req.getParameter(\"path\");",
        "int id = Integer.parseInt(request.getParameter(\"id\"));",
    ],
    'programming_language': ['java', 'java', 'java'],
    'cve_id': ['CVE-2021-001', 'CVE-2021-002', 'CVE-2021-003'],
    'hash': ['abc123', 'def456', 'ghi789'],
})

# 创建匹配器并查找相似模式
matcher = CodeSimilarityMatcher(shingle_size=5, use_ast=True)
similar_fixes_df, pattern_records_df = matcher.find_similar_fixes(
    df,
    top_n=10,
    similarity_threshold=0.5,
    similarity_method="combined",
    use_keyword_grouping=True,
    create_patterns=True,
)

print(f"找到 {len(similar_fixes_df)} 对相似的修复")
print(f"识别出 {len(pattern_records_df)} 个模式")
```

## 相关文档

- [VULNERABILITY_PATTERN_MINING.md](VULNERABILITY_PATTERN_MINING.md): 漏洞模式挖掘完整流程文档
- [README.md](README.md): 项目总体说明
- [DATABASE_TABLES_EXPLANATION.md](DATABASE_TABLES_EXPLANATION.md): 数据库表结构说明
