# MoreFixes 数据库表说明文档

本文档详细说明了 MoreFixes 数据库中每个表的作用、字段含义和数据内容。

## 数据库概览

数据库包含 **12 个表**，总共存储了超过 **100 万条记录**，涵盖了 CVE 漏洞信息、代码修复记录、仓库信息等。

## 表统计信息

| 表名 | 记录数 | 说明 |
|------|--------|------|
| fixes | 464,296 | 漏洞修复记录 |
| cve | 249,380 | CVE 漏洞信息 |
| cwe_classification | 253,162 | CVE-CWE 分类映射 |
| cve_cpe_mapper | 343,949 | CVE-CPE 映射关系 |
| method_change | 229,511 | 方法级别代码变更 |
| file_change | 103,703 | 文件级别代码变更 |
| cve_project | 92,467 | CVE-项目关联 |
| commits | 39,022 | Git 提交记录 |
| repository | 7,238 | 代码仓库信息 |
| cpe_project | 11,883 | CPE-项目关联 |
| cwe | 1,376 | CWE 弱点类型定义 |
| users | 0 | 用户表（当前为空） |

---

## 核心表详解

### 1. `fixes` - 漏洞修复记录表
**记录数**: 464,296  
**作用**: 存储每个 CVE 对应的修复提交记录，是数据库的核心表之一。

**字段说明**:
- `cve_id` (text): CVE 编号，如 "CVE-2020-28620"
- `hash` (text): Git commit hash，修复该漏洞的提交 ID
- `repo_url` (text): 代码仓库 URL，如 "https://github.com/CGAL/cgal"
- `rel_type` (text): 关联类型，表示 CVE 与修复提交的关联方式（详见下方 rel_type 说明）
- `score` (bigint): 关联评分，数值越高表示关联度越高（通常 >= 65）
- `extraction_status` (text): 提取状态，默认为 'NOT_STARTED'

**数据示例**:
```
CVE-2020-28620 | e1870c15224ddd5d79b1df5b8248e4c6813d7398 | https://github.com/CGAL/cgal | CPE_GIT_REPOBASED | 82
```

**关联关系**:
- 通过 `hash` 和 `repo_url` 关联到 `commits` 表
- 通过 `cve_id` 关联到 `cve` 表

---

### 2. `commits` - Git 提交记录表
**记录数**: 39,022  
**作用**: 存储 Git 提交的详细信息，包括作者、提交信息、代码变更统计等。

**字段说明**:
- `hash` (text): Git commit hash（主键之一）
- `repo_url` (text): 代码仓库 URL（主键之一）
- `author` (text): 提交作者
- `committer` (text): 提交者
- `msg` (text): 提交信息（commit message）
- `parents` (text): 父提交 hash
- `author_date` (timestamp): 作者提交时间
- `committer_date` (timestamp): 提交者提交时间
- `num_lines_added` (bigint): 新增代码行数
- `num_lines_deleted` (bigint): 删除代码行数
- `merge` (boolean): 是否为合并提交
- `dmm_unit_complexity` (double): 代码复杂度指标
- `dmm_unit_interfacing` (double): 接口复杂度指标
- `dmm_unit_size` (double): 代码大小指标

**关联关系**:
- 通过 `hash` 和 `repo_url` 关联到 `fixes` 表
- 通过 `hash` 关联到 `file_change` 表

---

### 3. `file_change` - 文件级别代码变更表
**记录数**: 103,703  
**作用**: 存储文件级别的代码变更信息，包括修改前后的代码、diff 信息等。

**字段说明**:
- `file_change_id` (text): 文件变更唯一标识
  - **格式**: 数字字符串（如 "202280460594685", "131461250543157"）
  - **唯一性**: 每个 `file_change_id` 都是唯一的（103,703 条记录，103,703 个唯一值）
  - **示例值**: `202280460594685`, `131461250543157`, `147219822889344`
- `hash` (text): 关联的 commit hash
- `filename` (text): 文件名
- `old_path` (text): 旧文件路径
- `new_path` (text): 新文件路径
- `change_type` (text): 变更类型（ADD、MODIFY、DELETE 等）
- `diff` (text): Git diff 原始内容
- `diff_parsed` (text): 解析后的 diff 信息
- `code_before` (text): **修复前的漏洞代码**（重要字段）
- `code_after` (text): **修复后的代码**（重要字段）
- `programming_language` (text): 编程语言（如 "Java"、"Go"、"Python" 等）
- `num_lines_added` (integer): 新增行数
- `num_lines_deleted` (integer): 删除行数
- `nloc` (text): 有效代码行数
- `complexity` (text): 代码复杂度
  - **数据类型**: 文本类型，但存储的是数字值或特殊值
  - **取值范围**: 
    - **特殊值**:
      - `nan` (24,483 条，23.61%): 表示无法计算复杂度（通常是非代码文件，如 Markdown、Shell 脚本等）
      - `None` (3,202 条，3.09%): NULL 值
    - **数值类型**:
      - **小数形式** (61,920 条): 如 `0.0`, `1.0`, `2.0`, `9.0`, `32.0`, `64.0`, `412.0`, `456.0` 等
      - **整数形式** (14,098 条): 如 `0`, `1`, `2`, `3`, `12`, `92`, `126` 等
      - **大数值**: 从 `0` 到 `87232.0` 不等，常见范围在 0-500 之间
  - **常见值**: 
    - `0.0` (6,137 条，5.92%)
    - `1.0` (1,655 条，1.60%)
    - `2.0` (1,619 条，1.56%)
    - `0` (1,530 条，1.48%)
    - `4.0` (1,322 条，1.27%)
    - `3.0` (1,266 条，1.22%)
  - **说明**: 复杂度值越大，表示代码越复杂。值为 `nan` 或 `None` 通常表示该文件无法进行复杂度分析（如配置文件、文档等）
- `token_count` (text): Token 数量

**关联关系**:
- 通过 `hash` 关联到 `commits` 表
- 通过 `file_change_id` 关联到 `method_change` 表

**用途**: 这是提取漏洞代码模式的主要数据源，`code_before` 字段包含漏洞代码，`code_after` 字段包含修复后的代码。

---

### 4. `method_change` - 方法级别代码变更表
**记录数**: 229,511  
**作用**: 存储方法级别的代码变更信息，提供更细粒度的代码分析。

**字段说明**:
- `method_change_id` (text): 方法变更唯一标识
- `file_change_id` (text): 关联的文件变更 ID
- `name` (text): 方法名
- `signature` (text): **方法签名**（重要字段，用于模式匹配）
- `parameters` (text): 方法参数
- `start_line` (text): 起始行号
- `end_line` (text): 结束行号
- `code` (text): 方法代码内容
- `before_change` (text): 变更前的代码
- `nloc` (text): 有效代码行数
- `complexity` (text): 代码复杂度
- `token_count` (text): Token 数量
- `top_nesting_level` (text): 最大嵌套层级

**关联关系**:
- 通过 `file_change_id` 关联到 `file_change` 表

**用途**: 用于基于方法签名的重复漏洞模式识别。

---

### 5. `cve` - CVE 漏洞信息表
**记录数**: 249,380  
**作用**: 存储 CVE（Common Vulnerabilities and Exposures）的详细信息，包括漏洞描述、严重程度、CVSS 评分等。

**字段说明**:
- `cve_id` (text): CVE 编号（主键）
- `published_date` (text): 发布日期
- `last_modified_date` (text): 最后修改日期
- `description` (text): 漏洞描述
- `severity` (text): 严重程度（LOW、MEDIUM、HIGH、CRITICAL）
- `cvss2_base_score` (text): CVSS v2 基础评分
- `cvss3_base_score` (text): CVSS v3 基础评分
- `cvss3_base_severity` (text): CVSS v3 严重程度
- `cvss2_vector_string` (text): CVSS v2 向量字符串
- `cvss3_vector_string` (text): CVSS v3 向量字符串
- `cvss2_access_vector` (text): CVSS v2 攻击向量
- `cvss3_attack_vector` (text): CVSS v3 攻击向量
- `cvss2_access_complexity` (text): CVSS v2 攻击复杂度
- `cvss3_attack_complexity` (text): CVSS v3 攻击复杂度
- `obtain_all_privilege` (text): 是否可获得所有权限
- `obtain_user_privilege` (text): 是否可获得用户权限
- `user_interaction_required` (text): 是否需要用户交互
- `reference_json` (text): 参考链接（JSON 格式）
- `problemtype_json` (text): 问题类型（JSON 格式）
- `nodes` (text): CVE 节点信息（JSON 格式）

**数据示例**:
```
CVE-1999-0001 | 1999-12-30T05:00Z | MEDIUM | nan
```

**关联关系**:
- 通过 `cve_id` 关联到 `fixes` 表
- 通过 `cve_id` 关联到 `cwe_classification` 表
- 通过 `cve_id` 关联到 `cve_cpe_mapper` 表
- 通过 `cve` 字段关联到 `cve_project` 表

---

### 6. `cwe` - CWE 弱点类型定义表
**记录数**: 1,376  
**作用**: 存储 CWE（Common Weakness Enumeration）弱点类型的定义信息。

**字段说明**:
- `index` (bigint): 索引
- `cwe_id` (text): CWE 编号（如 "CWE-79"）
- `cwe_name` (text): CWE 名称（如 "Cross-site Scripting (XSS)"）
- `description` (text): CWE 描述
- `extended_description` (text): 扩展描述
- `url` (text): CWE 官方链接
- `is_category` (boolean): 是否为类别

**关联关系**:
- 通过 `cwe_id` 关联到 `cwe_classification` 表

---

### 7. `cwe_classification` - CVE-CWE 分类映射表
**记录数**: 253,162  
**作用**: 建立 CVE 和 CWE 之间的映射关系，一个 CVE 可能对应多个 CWE。

**字段说明**:
- `cve_id` (text): CVE 编号
- `cwe_id` (text): CWE 编号

**关联关系**:
- 通过 `cve_id` 关联到 `cve` 表
- 通过 `cwe_id` 关联到 `cwe` 表

**用途**: 用于获取漏洞的弱点类型分类，帮助理解漏洞的本质。

---

### 8. `cve_cpe_mapper` - CVE-CPE 映射表
**记录数**: 343,949  
**作用**: 建立 CVE 和 CPE（Common Platform Enumeration）之间的映射关系，用于标识受影响的软件产品。

**字段说明**:
- `id` (integer): 主键（自增）
- `cve_id` (varchar): CVE 编号
- `cpe_name` (text): CPE 名称（如 "cpe:2.3:a:apache:struts:2.3.0:*:*:*:*:*:*:*"）

**关联关系**:
- 通过 `cve_id` 关联到 `cve` 表
- 通过 `cpe_name` 关联到 `cpe_project` 表

---

### 9. `cve_project` - CVE-项目关联表
**记录数**: 92,467  
**作用**: 建立 CVE 和项目（GitHub 仓库）之间的关联关系。

**字段说明**:
- `id` (integer): 主键（自增）
- `cve` (varchar): CVE 编号
- `project_url` (varchar): 项目 URL（通常是 GitHub 仓库 URL）
- `rel_type` (varchar): 关联类型
- `` (varchar): 是否已检查，默认为 'False'

**关联关系**:
- 通过 `cve` 关联到 `cve` 表
- 通过 `project_url` 关联到 `repository` 表

---

### 10. `cpe_project` - CPE-项目关联表
**记录数**: 11,883  
**作用**: 建立 CPE 和项目之间的关联关系。checked

**字段说明**:
- `cpe_name` (varchar): CPE 名称
- `repo_url` (varchar): 仓库 URL
- `rel_type` (varchar): 关联类型

**关联关系**:
- 通过 `cpe_name` 关联到 `cve_cpe_mapper` 表
- 通过 `repo_url` 关联到 `repository` 表

---

### 11. `repository` - 代码仓库信息表
**记录数**: 7,238  
**作用**: 存储代码仓库（主要是 GitHub 仓库）的元数据信息。

**字段说明**:
- `repo_url` (text): 仓库 URL（主键）
- `repo_name` (text): 仓库名称
- `description` (text): 仓库描述
- `date_created` (timestamp): 创建时间
- `date_last_push` (timestamp): 最后推送时间
- `homepage` (text): 主页 URL
- `repo_language` (text): 主要编程语言
- `owner` (text): 仓库所有者
- `forks_count` (bigint): Fork 数量
- `stars_count` (bigint): Star 数量

**关联关系**:
- 通过 `repo_url` 关联到 `commits` 表
- 通过 `repo_url` 关联到 `fixes` 表
- 通过 `project_url` 关联到 `cve_project` 表

---

### 12. `users` - 用户表
**记录数**: 0  
**作用**: 存储系统用户信息（当前为空表）。

**字段说明**:
- `id` (varchar): 用户 ID（主键）
- `hashed_password` (varchar): 加密后的密码
- `firstname` (varchar): 名
- `lastname` (varchar): 姓
- `photo` (varchar): 头像
- `account_created` (varchar): 账户创建时间
- `last_access` (varchar): 最后访问时间

---

## 数据关系图

```
cve (CVE信息)
  ├── fixes (修复记录) ──> commits (提交记录) ──> file_change (文件变更) ──> method_change (方法变更)
  ├── cwe_classification (CWE分类) ──> cwe (CWE定义)
  ├── cve_cpe_mapper (CPE映射) ──> cpe_project (CPE-项目关联) ──> repository (仓库信息)
  └── cve_project (CVE-项目关联) ──> repository (仓库信息)
```

## rel_type 字段说明

`rel_type` 字段出现在多个表中（`fixes`、`cve_project`、`cpe_project`），用于标识 CVE 与代码仓库/提交之间的关联方式。不同的关联类型表示不同的数据来源和匹配方法。

### fixes 表中的 rel_type（8 种类型）

| rel_type | 记录数 | 说明 |
|----------|--------|------|
| **CPE_GIT_REPOBASED** | 260,185 | 通过 CPE（Common Platform Enumeration）匹配到 Git 仓库，基于仓库级别的关联 |
| **NVD_GIT_REPOBASED** | 90,995 | 通过 NVD（National Vulnerability Database）匹配到 Git 仓库，基于仓库级别的关联 |
| **CPE_DIRECT_COMMIT** | 42,291 | 通过 CPE 直接匹配到具体的 Git commit |
| **GHSD_GIT_REPOBASED** | 21,781 | 通过 GHSD（GitHub Security Advisory）匹配到 Git 仓库，基于仓库级别的关联 |
| **CPE_GITHUB_SEARCH** | 18,993 | 通过 CPE 在 GitHub 上搜索匹配到的仓库 |
| **NVD_DIRECT_COMMIT** | 15,714 | 通过 NVD 直接匹配到具体的 Git commit |
| **GHSD_REGISTRY** | 9,876 | 通过 GHSD 在注册表中匹配到的项目 |
| **GHSD_DIRECT_COMMIT** | 4,461 | 通过 GHSD 直接匹配到具体的 Git commit |

**总计**: 464,296 条记录

### cve_project 表中的 rel_type（7 种类型）

| rel_type | 记录数 | 说明 |
|----------|--------|------|
| **CPE_GIT_REPOBASED** | 52,837 | CPE 与 Git 仓库的关联 |
| **NVD_GIT_REPOBASED** | 19,073 | NVD 与 Git 仓库的关联 |
| **CPE_DIRECT_COMMIT** | 10,780 | CPE 与直接 commit 的关联 |
| **CPE_GITHUB_SEARCH** | 4,435 | CPE 通过 GitHub 搜索的关联 |
| **GHSD_GIT_REPOBASED** | 3,665 | GHSD 与 Git 仓库的关联 |
| **GHSD_REGISTRY** | 1,676 | GHSD 与注册表的关联 |
| **NVD_REGISTRY** | 1 | NVD 与注册表的关联 |

**总计**: 92,467 条记录

### cpe_project 表中的 rel_type（3 种类型）

| rel_type | 记录数 | 说明 |
|----------|--------|------|
| **GIT_REPOBASED** | 10,328 | 基于 Git 仓库的关联 |
| **GITHUB_SEARCH** | 1,189 | 通过 GitHub 搜索的关联 |
| **DIRECT_COMMIT** | 366 | 直接 commit 的关联 |

**总计**: 11,883 条记录

### 关联类型含义解释

- **REPOBASED**: 基于仓库级别的关联，表示 CVE 与整个代码仓库相关
- **DIRECT_COMMIT**: 直接关联到具体的 commit，表示找到了修复该漏洞的具体提交
- **GITHUB_SEARCH**: 通过 GitHub 搜索功能找到的关联
- **REGISTRY**: 通过软件包注册表（如 npm、PyPI）找到的关联

### 数据来源说明

- **CPE**: Common Platform Enumeration，用于标识软件产品
- **NVD**: National Vulnerability Database，美国国家漏洞数据库
- **GHSD**: GitHub Security Advisory，GitHub 安全公告

### 使用建议

1. **REPOBASED** 类型：适合分析整个项目的漏洞修复模式
2. **DIRECT_COMMIT** 类型：适合精确分析特定漏洞的修复代码
3. **GITHUB_SEARCH** 类型：可能包含一些间接关联，使用时需要额外验证
4. 在查询时可以根据 `rel_type` 过滤，选择更可靠的数据来源

## 典型查询流程

### 1. 提取漏洞代码模式（如 extract_recurring_vulnerabilities.py）

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

### 2. 获取 CVE 的 CWE 分类

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

## 注意事项

1. **数据量**: `fixes` 表是最大的表（46万+记录），查询时注意性能优化
2. **代码字段**: `file_change.code_before` 和 `file_change.code_after` 字段可能包含大量文本，查询时注意内存使用
3. **关联查询**: 多个表 JOIN 时注意索引使用，主要索引在 `cve_id`、`hash`、`repo_url` 等字段上
4. **空值处理**: 某些字段可能为 NULL，查询时注意处理
5. **编程语言**: `file_change.programming_language` 字段用于过滤特定语言的代码

## 参考

- MoreFixes 论文: https://dl.acm.org/doi/abs/10.1145/3663533.3664036
- CVE 数据库: https://cve.mitre.org/
- CWE 数据库: https://cwe.mitre.org/
- CPE 规范: https://nvd.nist.gov/products/cpe

