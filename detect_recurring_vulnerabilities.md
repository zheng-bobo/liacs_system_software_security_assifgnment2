# 提取候选重复漏洞代码模式

从 MoreFixes 数据库中提取 Java 的漏洞代码，识别重复模式。

## 1. 数据筛选 (SQL)

### 筛选条件

a. **fixes.score >= 65**  
   score ≥ 65 时，准确率约在 95%+

b. **file_change.diff 非空**  
   确保有代码差异信息

c. **commits.merge = false**  
   排除 merge commit（合并提交）

### SQL 查询示例

```sql
-- 取"可用于模式挖掘"的高质量修复样本
WITH good_fixes AS (
  SELECT f.cve_id, f.hash, f.repo_url, f.score
  FROM fixes f
  WHERE f.score >= 65
)
SELECT
  gf.cve_id,
  gf.repo_url,
  gf.hash,
  c.author_date,
  c.msg,
  fc.file_change_id,
  fc.filename,
  fc.programming_language,
  fc.code_before,
  fc.code_after
FROM good_fixes gf
JOIN commits c
  ON c.hash = gf.hash AND c.repo_url = gf.repo_url
JOIN file_change fc
  ON fc.hash = gf.hash
WHERE COALESCE(fc.diff, '') <> ''
  AND COALESCE(c.merge, FALSE) = FALSE
  AND fc.programming_language IN ('Java');
```

## 2. 特征工程

### 2.1 代码预处理

在提取差异之前，先对 `code_before` 与 `code_after` 进行语法与格式标准化，保证来自不同项目的代码可对齐。

#### 处理步骤

- **去除注释与空行**（不影响语义但会干扰 diff）
- **统一命名与常量格式**：
  - 变量名 → `VAR_x`
  - 方法名 → `FUNC_x`
  - 类名 → `CLASS_x`
- **字面量统一**：
  - 数字 → `NUM`
  - 字符串 → `STR`
- **格式归一化**：统一缩进与花括号样式
- **按语言分词**：用语言特定的 tokenizer（如 Java 的 tree-sitter-java）

> 🔹 **目的**：让"语义相同但命名不同"的修复动作在不同项目中能对齐。

### 2.2 语法级差异分析（AST Diff）

对 `code_before` 和 `code_after` 进行 AST（抽象语法树）解析，并通过结构对比生成一系列语义化的**编辑动作**（edit actions）。

#### 可用工具

- **tree-sitter-java**（轻量快速）
- **GumTree**（经典、成熟）

#### 生成的编辑动作类型

- **INSERT**：新增语句或节点
- **DELETE**：删除语句或节点
- **UPDATE**：修改表达式或调用
- **MOVE**：语句重排

### 2.3 编辑动作抽象化（Action Abstraction）

将语法 diff 的结果抽象成通用的 Java 修复动作模板 token。

#### 动作映射表

| 原始差异 | 抽象化后 token |
|---------|---------------|
| INSERT IfStatement(condition: x != null) | `ADD_IF_NULLCHECK` |
| REPLACE println(userInput) → println(escapeHtml(userInput)) | `WRAP_WITH_SANITIZER` |
| REPLACE Statement: new File(path) → new File(baseDir, path) | `ADD_PATH_VALIDATION` |
| INSERT TryCatch(Exception) | `ADD_EXCEPTION_HANDLING` |
| REPLACE call: Statement.execute(...) → PreparedStatement | `REPLACE_API_SQL_TO_PREPARED` |

每个 token 表示一种修复语义（如增加空指针检查、添加输入验证、替换危险 API）。

### 2.5 特征向量化

将每次修复的 `edit_actions` 转化为机器可比较的特征向量。

#### 向量化方法

- **词袋模型（Bag-of-Actions）**：统计各修复动作出现次数
- **n-gram 序列**：捕捉连续动作的上下文
- **TF-IDF 向量化**：衡量修复动作的全局重要性
- **（可选）嵌入模型**：使用 CodeBERT 等模型对 `code_before → code_after` 表示为语义向量

#### 输出格式示例

```json
{
  "cve_id": "CVE-2021-12345",
  "repo_url": "https://github.com/example/project",
  "edit_actions": ["ADD_IF_NULLCHECK", "WRAP_WITH_SANITIZER"],
  "vector": [0.82, 0.63, 0.00, 0.00],
  "metadata": {
    "cwe": ["CWE-79"],
    "cvss": 7.5
  }
}
```

## 3. 重复修复模式识别

### 3.1 分组统计

当所有修复样本都转化为特征表示后，进行统计与聚类分析。

将相同或高度相似的编辑动作序列视为同一修复模板：

```python
df["pattern"] = df["edit_actions"].apply(lambda x: " ".join(sorted(set(x))))
pattern_stats = (
    df.groupby("pattern")
      .agg(count=("pattern","count"),
           cves=("cve_id", lambda s: list(set(s))),
           repos=("repo_url", lambda s: list(set(s))))
      .reset_index()
      .sort_values(by="count", ascending=False)
)
```

选取重复次数最高的前 N 个模板作为**候选重复漏洞修复模式**（candidate recurring fix patterns）。

#### 代码片段聚类（可选）

若需更细粒度分析，可基于 `code_before` 的 TF-IDF 向量做相似度聚类，找出在不同项目中出现的"相似漏洞代码块"，代表潜在重复漏洞模式。

### 3.2 输出结果

| rank | pattern | count | CWE | example CVEs |
|------|---------|-------|-----|--------------|
| 1 | ADD_IF_NULLCHECK WRAP_WITH_SANITIZER | 137 | CWE-79 | CVE-2019-1234, CVE-2020-5678 |
| 2 | REPLACE_API_SQL_TO_PREPARED | 94 | CWE-89 | CVE-2018-9999, CVE-2021-1111 |
| 3 | ADD_EXCEPTION_HANDLING | 77 | CWE-248 | CVE-2017-3333, CVE-2020-8888 |

这些高频模式代表了跨多个 Java 项目反复出现的漏洞修复模板，可视为**候选重复漏洞**（candidate recurring vulnerabilities）。
