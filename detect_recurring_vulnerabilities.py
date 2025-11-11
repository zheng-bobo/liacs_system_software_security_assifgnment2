#!/usr/bin/env python3
"""
Extracting Candidate Recurring Vulnerability Code Patterns

Extract Java vulnerability code from the MoreFixes database and identify recurring repair patterns.

Workflow:
1. Data Filtering: Extract high-quality fix samples from the database (score >= 65, non-empty diff, exclude merge commits)
2. Feature Engineering:
   - Code Preprocessing: Standardize code style, normalize identifiers, unify literals
   - AST Diff: Parse code differences and generate edit actions (INSERT/DELETE/UPDATE/MOVE)
   - Action Abstraction: Abstract edit actions into repair action tokens (such as ADD_IF_NULLCHECK, WRAP_WITH_SANITIZER)
   - Feature Vectorization: Use bag-of-words or TF-IDF to convert action sequences to vectors
3. Pattern Identification: Count occurrences of identical repair patterns and identify candidate recurring vulnerabilities

For details, please refer to detect_recurring_vulnerabilities.md
"""

import os
import sys
import re
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import logging
import hashlib
import argparse
from dotenv import load_dotenv
import pandas as pd
import sqlalchemy
from sqlalchemy import text
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np


# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

# 加载环境变量
load_dotenv(".env")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("detect_recurring_vulnerabilities.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class DatabaseConnector:
    """Database connector"""

    def __init__(self):
        self.engine = None
        self._connect()

    def _connect(self):
        """Connect to the database"""
        try:
            db_url = (
                f'postgresql://{os.getenv("POSTGRES_USER")}:'
                f'{os.getenv("POSTGRES_PASSWORD")}@'
                f'{os.getenv("DB_HOST")}:{os.getenv("POSTGRES_PORT")}/'
                f'{os.getenv("POSTGRES_DB")}'
            )
            self.engine = sqlalchemy.create_engine(db_url)
            logger.info("Database connected successfully")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            sys.exit(1)

    def execute_query(self, query: str, params: Optional[dict] = None) -> pd.DataFrame:
        """Execute query and return DataFrame"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text(query), params or {})
                return pd.DataFrame(result.fetchall(), columns=result.keys())
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise


class FeatureEngineering:
    """
    特征工程类：实现代码预处理、AST Diff、编辑动作抽象化、特征向量化和重复模式识别
    """

    def __init__(self, use_ast_diff: bool = False):
        """
        初始化特征工程类

        Args:
            use_ast_diff: 是否使用 AST Diff（需要 tree-sitter 或 GumTree），默认 False
        """
        self.use_ast_diff = use_ast_diff
        self.var_counter = 0
        self.func_counter = 0
        self.class_counter = 0
        self.action_patterns = self._init_action_patterns()
        self.vectorizer = None

    def _init_action_patterns(self) -> Dict[str, str]:
        """初始化编辑动作模式映射"""
        return {
            # 空指针检查模式
            r"if\s*\(\s*\w+\s*!=\s*null\s*\)": "ADD_IF_NULLCHECK",
            r"if\s*\(\s*null\s*!=\s*\w+\s*\)": "ADD_IF_NULLCHECK",
            # 输入验证/清理模式
            r"escapeHtml\s*\(": "WRAP_WITH_SANITIZER",
            r"sanitize\s*\(": "WRAP_WITH_SANITIZER",
            r"validate\s*\(": "ADD_INPUT_VALIDATION",
            # 路径验证模式
            r"new\s+File\s*\([^)]*,\s*[^)]+\)": "ADD_PATH_VALIDATION",
            # 异常处理模式
            r"try\s*\{": "ADD_EXCEPTION_HANDLING",
            r"catch\s*\([^)]*Exception": "ADD_EXCEPTION_HANDLING",
            # SQL 注入防护模式
            r"PreparedStatement": "REPLACE_API_SQL_TO_PREPARED",
            r"Statement\.execute": "REPLACE_API_SQL_TO_PREPARED",
        }

    def preprocess_code(self, code: str) -> str:
        """
        2.1 代码预处理：标准化代码格式

        Args:
            code: 原始代码

        Returns:
            标准化后的代码
        """
        if code is None or (isinstance(code, float) and pd.isna(code)) or code == "":
            return ""

        # 去除注释（单行和多行）
        code = re.sub(r"//.*?$", "", code, flags=re.MULTILINE)
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

        # 去除空行
        lines = [line.strip() for line in code.split("\n") if line.strip()]
        code = "\n".join(lines)

        # 统一缩进（使用4个空格）
        lines = code.split("\n")
        normalized_lines = []
        indent_level = 0
        for line in lines:
            stripped = line.lstrip()
            if not stripped:
                continue

            # 计算缩进级别
            if stripped.startswith("}"):
                indent_level = max(0, indent_level - 1)

            normalized_lines.append(" " * (indent_level * 4) + stripped)

            # 更新缩进级别
            if stripped.endswith("{"):
                indent_level += 1
            elif stripped.startswith("}"):
                pass  # 已经在上面处理了

        code = "\n".join(normalized_lines)

        # 统一花括号样式（统一为同一行）
        code = re.sub(r"\{[\s]*\n", "{ ", code)
        code = re.sub(r"\n[\s]*\}", " }", code)

        return code

    def normalize_identifiers(self, code: str) -> str:
        """
        统一命名格式：变量名 → VAR_x，方法名 → FUNC_x，类名 → CLASS_x

        Args:
            code: 预处理后的代码

        Returns:
            标识符归一化后的代码
        """
        # 重置计数器
        self.var_counter = 0
        self.func_counter = 0
        self.class_counter = 0

        var_map = {}
        func_map = {}
        class_map = {}

        # 识别并替换变量名（简单模式匹配）
        # 匹配 Java 变量声明：类型 变量名 = ...
        var_pattern = r"\b(int|String|boolean|long|double|float|char|byte|short|Object|List|Map|Set)\s+(\w+)\s*[=;]"
        for match in re.finditer(var_pattern, code):
            var_name = match.group(2)
            if var_name not in var_map:
                var_map[var_name] = f"VAR_{self.var_counter}"
                self.var_counter += 1
            code = code.replace(var_name, var_map[var_name])

        # 识别并替换方法名（简单模式匹配）
        func_pattern = r"\b(public|private|protected)?\s*(static)?\s*\w+\s+(\w+)\s*\("
        for match in re.finditer(func_pattern, code):
            func_name = match.group(3)
            if func_name not in func_map and func_name not in [
                "if",
                "for",
                "while",
                "switch",
            ]:
                func_map[func_name] = f"FUNC_{self.func_counter}"
                self.func_counter += 1
            if func_name in func_map:
                code = code.replace(func_name + "(", func_map[func_name] + "(")

        # 识别并替换类名
        class_pattern = r"\bclass\s+(\w+)"
        for match in re.finditer(class_pattern, code):
            class_name = match.group(1)
            if class_name not in class_map:
                class_map[class_name] = f"CLASS_{self.class_counter}"
                self.class_counter += 1
            code = code.replace(class_name, class_map[class_name])

        # 统一字面量：数字 → NUM，字符串 → STR
        code = re.sub(r"\b\d+\.?\d*\b", "NUM", code)
        code = re.sub(r'"[^"]*"', "STR", code)
        code = re.sub(r"'[^']*'", "STR", code)

        return code

    def extract_ast_diff(self, code_before: str, code_after: str) -> List[str]:
        """
        2.2 语法级差异分析（AST Diff）

        Args:
            code_before: 修复前的代码
            code_after: 修复后的代码

        Returns:
            编辑动作列表（INSERT, DELETE, UPDATE, MOVE）
        """
        if not self.use_ast_diff:
            # 简化版本：基于文本差异
            return self._simple_diff(code_before, code_after)

        # TODO: 集成 tree-sitter-java 或 GumTree 进行真正的 AST Diff
        # 这里返回简化版本
        return self._simple_diff(code_before, code_after)

    def _simple_diff(self, code_before: str, code_after: str) -> List[str]:
        """简化的文本差异分析"""
        actions = []
        before_lines = set(code_before.split("\n"))
        after_lines = set(code_after.split("\n"))

        # 找出新增的行
        added = after_lines - before_lines
        if added:
            actions.append("INSERT")

        # 找出删除的行
        removed = before_lines - after_lines
        if removed:
            actions.append("DELETE")

        # 如果有变化，标记为 UPDATE
        if added or removed:
            actions.append("UPDATE")

        return actions if actions else ["NO_CHANGE"]

    def abstract_edit_actions(self, code_before: str, code_after: str) -> List[str]:
        """
        2.3 编辑动作抽象化：将差异抽象成修复动作 token

        Args:
            code_before: 修复前的代码
            code_after: 修复后的代码

        Returns:
            抽象化的编辑动作 token 列表
        """
        actions = set()

        # 预处理代码
        before_normalized = self.normalize_identifiers(
            self.preprocess_code(code_before)
        )
        after_normalized = self.normalize_identifiers(self.preprocess_code(code_after))

        # 分析新增的代码模式
        after_lines = after_normalized.split("\n")
        for line in after_lines:
            for pattern, action_token in self.action_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    actions.add(action_token)

        # 检查是否有新增的 if null check
        if "if" in after_normalized.lower() and "null" in after_normalized.lower():
            if (
                "if" not in before_normalized.lower()
                or "null" not in before_normalized.lower()
            ):
                actions.add("ADD_IF_NULLCHECK")

        # 检查是否有新增的 try-catch
        if "try" in after_normalized.lower() and "catch" in after_normalized.lower():
            if "try" not in before_normalized.lower():
                actions.add("ADD_EXCEPTION_HANDLING")

        # 检查 SQL 相关变化
        if (
            "PreparedStatement" in after_normalized
            and "PreparedStatement" not in before_normalized
        ):
            actions.add("REPLACE_API_SQL_TO_PREPARED")

        return sorted(list(actions)) if actions else ["UNKNOWN_ACTION"]

    def vectorize_features(
        self, edit_actions: List[str], method: str = "bag_of_actions"
    ) -> np.ndarray:
        """
        2.5 特征向量化：将编辑动作转化为特征向量

        Args:
            edit_actions: 编辑动作列表
            method: 向量化方法 ('bag_of_actions', 'tfidf')

        Returns:
            特征向量
        """
        if method == "bag_of_actions":
            # 词袋模型：统计各修复动作出现次数
            # 这里简化处理，返回动作的 one-hot 编码
            all_actions = [
                "ADD_IF_NULLCHECK",
                "WRAP_WITH_SANITIZER",
                "ADD_INPUT_VALIDATION",
                "ADD_PATH_VALIDATION",
                "ADD_EXCEPTION_HANDLING",
                "REPLACE_API_SQL_TO_PREPARED",
                "UNKNOWN_ACTION",
            ]
            vector = np.zeros(len(all_actions))
            for i, action in enumerate(all_actions):
                if action in edit_actions:
                    vector[i] = edit_actions.count(action)
            return vector

        elif method == "tfidf":
            # TF-IDF 向量化（需要先 fit）
            if self.vectorizer is None:
                raise ValueError(
                    "TF-IDF vectorizer not fitted. Call fit_vectorizer first."
                )
            action_str = " ".join(edit_actions)
            return self.vectorizer.transform([action_str]).toarray()[0]

        return np.array([])

    def fit_vectorizer(self, all_edit_actions: List[List[str]]):
        """
        训练 TF-IDF 向量化器

        Args:
            all_edit_actions: 所有样本的编辑动作列表
        """
        action_strings = [" ".join(actions) for actions in all_edit_actions]
        self.vectorizer = TfidfVectorizer()
        self.vectorizer.fit(action_strings)

    def process_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        处理整个 DataFrame，添加特征列

        Args:
            df: 包含 code_before 和 code_after 的 DataFrame

        Returns:
            添加了特征列的 DataFrame
        """
        logger.info("开始特征工程处理...")

        # 提取编辑动作
        logger.info("提取编辑动作...")
        df["edit_actions"] = df.apply(
            lambda row: self.abstract_edit_actions(
                str(row.get("code_before", "")), str(row.get("code_after", ""))
            ),
            axis=1,
        )

        # 生成模式字符串（用于分组）
        df["pattern"] = df["edit_actions"].apply(
            lambda x: " ".join(sorted(set(x))) if isinstance(x, list) else ""
        )

        # 向量化（使用词袋模型）
        logger.info("生成特征向量...")
        all_actions = df["edit_actions"].tolist()
        df["vector"] = df["edit_actions"].apply(
            lambda x: self.vectorize_features(x, method="bag_of_actions").tolist()
        )

        logger.info(f"特征工程完成，处理了 {len(df)} 条记录")
        return df

    def identify_recurring_patterns(
        self, df: pd.DataFrame, top_n: int = 10
    ) -> pd.DataFrame:
        """
        3.1 重复修复模式识别

        Args:
            df: 包含 edit_actions 和 pattern 列的 DataFrame
            top_n: 返回前 n 个最常见的模式

        Returns:
            重复模式统计 DataFrame
        """
        logger.info("开始识别重复修复模式...")

        # 分组统计
        pattern_stats = (
            df.groupby("pattern")
            .agg(
                count=("pattern", "count"),
                cves=("cve_id", lambda s: list(set(s))[:10]),  # 只保留前10个
                repos=("repo_url", lambda s: list(set(s))[:5]),  # 只保留前5个
                unique_cves=("cve_id", "nunique"),
                unique_commits=("hash", "nunique"),
                unique_repos=("repo_url", "nunique"),
            )
            .reset_index()
            .sort_values(by="count", ascending=False)
        )

        # 添加排名
        pattern_stats["rank"] = range(1, len(pattern_stats) + 1)

        # 返回前 n 个
        top_patterns = pattern_stats.head(top_n).copy()

        logger.info(f"识别出 {len(pattern_stats)} 个修复模式")
        logger.info(f"返回前 {len(top_patterns)} 个最常见的模式")

        return top_patterns


def extract_java_vulnerable_code(
    db_connector: DatabaseConnector,
    min_score: int = 65,
    exclude_merge_commits: bool = True,
    programming_languages: list = None,
    require_diff: bool = True,
) -> pd.DataFrame:
    """
    从数据库中提取指定语言的漏洞代码

    Args:
        db_connector: 数据库连接器
        min_score: fixes.score 的最小值，默认 65 (准确率约在 95%+)
        exclude_merge_commits: 是否排除 merge commit，默认 True
        programming_languages: 编程语言列表，默认 ['Java']
        require_diff: 是否要求 diff 非空，默认 True

    Returns:
        包含漏洞代码信息的 DataFrame
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info(f"开始提取 {programming_languages} 语言的漏洞代码...")
    logger.info(
        f"筛选条件: min_score={min_score}, exclude_merge={exclude_merge_commits}, require_diff={require_diff}"
    )

    # 构建语言过滤条件（不区分大小写匹配）
    # 允许传入 "java"、"JAVA"、"Java" 等不同大小写的值，都能匹配到数据库中的记录
    lang_conditions = []
    for i, lang in enumerate(programming_languages):
        # 使用 LOWER() 函数进行不区分大小写匹配，使用参数化查询避免 SQL 注入
        lang_conditions.append(f"LOWER(fc.programming_language) = LOWER(:lang_{i})")

    # 准备参数
    params = {"min_score": min_score}
    for i, lang in enumerate(programming_languages):
        params[f"lang_{i}"] = lang

    lang_filter = " OR ".join(lang_conditions)

    # 构建 WHERE 条件
    where_conditions = []

    # diff 条件
    if require_diff:
        where_conditions.append("COALESCE(fc.diff, '') <> ''")

    # merge commit 条件
    if exclude_merge_commits:
        where_conditions.append("COALESCE(c.merge, FALSE) = FALSE")

    # 编程语言条件（不区分大小写）
    where_conditions.append(f"({lang_filter})")

    where_clause = " AND ".join(where_conditions)

    query = f"""
    -- 取"可用于模式挖掘"的高质量修复样本
    WITH good_fixes AS (
      SELECT f.cve_id, f.hash, f.repo_url, f.score
      FROM fixes f
      WHERE f.score >= :min_score
    )
    SELECT
      gf.cve_id,
      gf.repo_url,
      gf.hash,
      gf.score,
      c.author_date,
      c.msg,
      fc.file_change_id,
      fc.filename,
      fc.programming_language,
      fc.code_before,
      fc.code_after,
      fc.diff
    FROM good_fixes gf
    JOIN commits c
      ON c.hash = gf.hash AND c.repo_url = gf.repo_url
    JOIN file_change fc
      ON fc.hash = gf.hash
    WHERE {where_clause};
    """

    df = db_connector.execute_query(query, params=params)

    logger.info(f"提取了 {len(df)} 条漏洞代码记录")
    logger.info(f"涉及 {df['cve_id'].nunique()} 个 CVE")
    logger.info(f"涉及 {df['hash'].nunique()} 个 commit")
    logger.info(f"涉及 {df['repo_url'].nunique()} 个仓库")

    return df


def identify_recurring_patterns(
    df: pd.DataFrame,
    top_n: int = 3,
    use_code_hash: bool = True,
) -> pd.DataFrame:
    """
    识别重复出现的漏洞代码模式，返回出现次数最多的 n 个模式

    Args:
        df: 包含漏洞代码的 DataFrame
        top_n: 返回前 n 个最常见的模式，默认 3
        use_code_hash: 是否使用代码哈希来识别重复模式，默认 True

    Returns:
        包含重复模式信息的 DataFrame，按出现次数降序排列
    """
    logger.info(f"开始识别重复漏洞代码模式...")
    logger.info(f"参数: top_n={top_n}")

    # 计算代码哈希
    if use_code_hash:
        df["code_hash"] = df["code_before"].apply(
            lambda x: (
                hashlib.sha256(str(x).encode("utf-8")).hexdigest()
                if pd.notna(x) and x != ""
                else None
            )
        )
        group_key = "code_hash"
    else:
        # 直接使用 code_before 作为分组键
        group_key = "code_before"

    # 过滤掉空值
    df_filtered = df[df[group_key].notna()].copy()

    # 按代码模式分组，统计出现次数
    pattern_stats = []
    for pattern_value, group in df_filtered.groupby(group_key):
        occurrences = len(group)
        # 获取该模式的相关信息
        first_row = group.iloc[0]
        pattern_stats.append(
            {
                "pattern_id": (
                    pattern_value[:16] if use_code_hash else str(pattern_value)[:50]
                ),
                "code_hash": (
                    pattern_value
                    if use_code_hash
                    else hashlib.sha256(str(pattern_value).encode("utf-8")).hexdigest()
                ),
                "occurrences": occurrences,
                "unique_cves": group["cve_id"].nunique(),
                "unique_commits": group["hash"].nunique(),
                "unique_repos": group["repo_url"].nunique(),
                "unique_files": group["filename"].nunique(),
                "programming_language": first_row["programming_language"],
                "code_before": (
                    first_row["code_before"][:500]
                    if pd.notna(first_row["code_before"])
                    else ""
                ),  # 只保存前500字符
                "code_after": (
                    first_row["code_after"][:500]
                    if pd.notna(first_row["code_after"])
                    else ""
                ),
                "cve_ids": list(group["cve_id"].unique())[:10],  # 只保存前10个CVE ID
                "repo_urls": list(group["repo_url"].unique())[:5],  # 只保存前5个仓库URL
            }
        )

    # 转换为 DataFrame 并按出现次数排序
    patterns_df = pd.DataFrame(pattern_stats)
    if len(patterns_df) == 0:
        logger.warning("未找到重复模式")
        return pd.DataFrame()

    patterns_df = patterns_df.sort_values("occurrences", ascending=False)

    # 返回前 n 个
    top_patterns = patterns_df.head(top_n).copy()

    logger.info(f"识别出 {len(patterns_df)} 个代码模式")
    logger.info(f"返回前 {len(top_patterns)} 个最常见的模式")

    return top_patterns


def process_recurring_patterns(
    vulnerable_code_df: pd.DataFrame,
    top_n: int = 3,
    output_dir: Path = None,
    use_feature_engineering: bool = True,
    use_code_hash: bool = False,
) -> pd.DataFrame:
    """
    步骤2: 识别重复漏洞代码模式并保存结果

    Args:
        vulnerable_code_df: 包含漏洞代码的 DataFrame
        top_n: 返回前 n 个最常见的模式，默认 3
        output_dir: 输出目录，默认 None（使用当前目录下的 output 目录）
        use_feature_engineering: 是否使用特征工程方法，默认 True
        use_code_hash: 是否使用代码哈希来识别重复模式（旧方法），默认 False

    Returns:
        包含重复模式信息的 DataFrame，按出现次数降序排列
    """
    logger.info("\n步骤2: 识别重复漏洞代码模式")

    # 设置输出目录
    if output_dir is None:
        output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    if use_feature_engineering:
        # 使用特征工程方法
        logger.info("使用特征工程方法识别重复模式...")
        feature_eng = FeatureEngineering(use_ast_diff=False)

        # 处理 DataFrame，添加特征列
        df_with_features = feature_eng.process_dataframe(vulnerable_code_df.copy())

        # 识别重复修复模式
        recurring_patterns_df = feature_eng.identify_recurring_patterns(
            df_with_features, top_n=top_n
        )

        # 保存带特征的完整数据（排除 code_before 和 code_after 列以减小文件大小）
        features_file = output_dir / "vulnerable_code_with_features.csv"
        # 转换列表列为字符串以便保存，并排除 code_before 和 code_after
        df_to_save = df_with_features.copy()
        columns_to_save = [
            col
            for col in df_to_save.columns
            if col not in ["code_before", "code_after"]
        ]
        df_to_save = df_to_save[columns_to_save].copy()

        if "edit_actions" in df_to_save.columns:
            df_to_save["edit_actions"] = df_to_save["edit_actions"].apply(
                lambda x: ", ".join(x) if isinstance(x, list) else str(x)
            )
        if "vector" in df_to_save.columns:
            df_to_save["vector"] = df_to_save["vector"].apply(
                lambda x: str(x) if isinstance(x, (list, np.ndarray)) else str(x)
            )
        df_to_save.to_csv(features_file, index=False, encoding="utf-8")
        logger.info(f"带特征的数据已保存到: {features_file}")
        logger.info(f"已排除 code_before 和 code_after 列以减小文件大小")

    else:
        # 使用旧的代码哈希方法
        logger.info("使用代码哈希方法识别重复模式...")
        recurring_patterns_df = identify_recurring_patterns(
            vulnerable_code_df,
            top_n=top_n,
            use_code_hash=use_code_hash,
        )

    # 保存重复模式结果
    if len(recurring_patterns_df) > 0:
        # 将列表类型的列转换为字符串以便保存到 CSV
        patterns_df_to_save = recurring_patterns_df.copy()
        if "cves" in patterns_df_to_save.columns:
            patterns_df_to_save["cves"] = patterns_df_to_save["cves"].apply(
                lambda x: ", ".join(x) if isinstance(x, list) else str(x)
            )
        if "repos" in patterns_df_to_save.columns:
            patterns_df_to_save["repos"] = patterns_df_to_save["repos"].apply(
                lambda x: ", ".join(x) if isinstance(x, list) else str(x)
            )
        if "cve_ids" in patterns_df_to_save.columns:
            patterns_df_to_save["cve_ids"] = patterns_df_to_save["cve_ids"].apply(
                lambda x: ", ".join(x) if isinstance(x, list) else str(x)
            )
        if "repo_urls" in patterns_df_to_save.columns:
            patterns_df_to_save["repo_urls"] = patterns_df_to_save["repo_urls"].apply(
                lambda x: ", ".join(x) if isinstance(x, list) else str(x)
            )

        patterns_file = output_dir / f"recurring_patterns_top{top_n}.csv"
        patterns_df_to_save.to_csv(patterns_file, index=False, encoding="utf-8")
        logger.info(f"重复模式结果已保存到: {patterns_file}")

        # 打印前几个模式的详细信息
        logger.info("\n" + "=" * 60)
        logger.info(f"前 {min(5, len(recurring_patterns_df))} 个最常见的重复模式:")
        logger.info("=" * 60)
        for idx, (_, row) in enumerate(recurring_patterns_df.head(5).iterrows(), 1):
            logger.info(f"\n模式 #{idx}:")
            if "count" in row:
                logger.info(f"  出现次数: {row['count']}")
            elif "occurrences" in row:
                logger.info(f"  出现次数: {row['occurrences']}")
            if "unique_cves" in row:
                logger.info(f"  涉及 CVE 数: {row['unique_cves']}")
            if "unique_commits" in row:
                logger.info(f"  涉及 commit 数: {row['unique_commits']}")
            if "unique_repos" in row:
                logger.info(f"  涉及仓库数: {row['unique_repos']}")
            if "pattern" in row:
                logger.info(f"  修复模式: {row['pattern']}")
            if "code_hash" in row:
                logger.info(f"  代码哈希: {row['code_hash'][:32]}...")
            if "code_before" in row:
                logger.info(f"  代码预览: {row['code_before'][:100]}...")

    return recurring_patterns_df


def main(
    top_n: int = 3,
    min_score: int = 65,
    exclude_merge_commits: bool = True,
    programming_languages: List[str] = None,
    require_diff: bool = True,
):
    """
    主函数：提取候选重复漏洞代码模式

    Args:
        top_n: 返回出现次数最多的前 n 个模式，默认 3
        min_score: fixes.score 的最小值，默认 65
        exclude_merge_commits: 是否排除 merge commit，默认 True
        programming_languages: 编程语言列表，默认 ['Java']
        require_diff: 是否要求 diff 非空，默认 True
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info("=" * 60)
    logger.info("开始提取候选重复漏洞代码模式")
    logger.info(f"配置: top_n={top_n}, min_score={min_score}")
    logger.info("=" * 60)

    # 初始化数据库连接
    db_connector = DatabaseConnector()

    # 步骤1: 根据条件筛选漏洞代码
    logger.info("\n步骤1: 提取漏洞代码")
    vulnerable_code_df = extract_java_vulnerable_code(
        db_connector,
        min_score=min_score,
        exclude_merge_commits=exclude_merge_commits,
        programming_languages=programming_languages,
        require_diff=require_diff,
    )

    # 保存原始数据（排除 code_before 和 code_after 列，但包含 score 列）
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 准备要保存的列：排除 code_before 和 code_after
    columns_to_save = [
        col
        for col in vulnerable_code_df.columns
        if col not in ["code_before", "code_after"]
    ]
    output_df = vulnerable_code_df[columns_to_save].copy()

    output_file = output_dir / "extract_java_vulnerable_code.csv"
    output_df.to_csv(output_file, index=False, encoding="utf-8")
    logger.info(f"原始数据已保存到: {output_file}")

    # 步骤2: 识别重复模式
    recurring_patterns_df = process_recurring_patterns(
        vulnerable_code_df,
        top_n=top_n,
        output_dir=output_dir,
        use_code_hash=True,
    )

    # 打印统计信息
    logger.info("\n" + "=" * 60)
    logger.info("统计信息:")
    logger.info(f"  总记录数: {len(vulnerable_code_df)}")
    logger.info(f"  唯一 CVE 数: {vulnerable_code_df['cve_id'].nunique()}")
    logger.info(f"  唯一 commit 数: {vulnerable_code_df['hash'].nunique()}")
    logger.info(f"  唯一仓库数: {vulnerable_code_df['repo_url'].nunique()}")
    logger.info(f"  唯一文件数: {vulnerable_code_df['filename'].nunique()}")
    logger.info(f"  识别出的重复模式数: {len(recurring_patterns_df)}")
    logger.info("=" * 60)

    logger.info("\n提取完成！")


def parse_arguments():
    """
    解析命令行参数

    Returns:
        argparse.Namespace: 解析后的命令行参数对象
    """
    parser = argparse.ArgumentParser(description="提取候选重复漏洞代码模式")
    parser.add_argument(
        "--top-n",
        type=int,
        default=3,
        help="返回出现次数最多的前 n 个模式（默认: 3）",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=65,
        help="fixes.score 的最小值（默认: 65）",
    )
    parser.add_argument(
        "--include-merge",
        action="store_true",
        help="包含 merge commit（默认: 排除）",
    )
    parser.add_argument(
        "--languages",
        nargs="+",
        default=["java"],  # 可以使用任何大小写形式，如 "java"、"JAVA"、"Java"
        help="编程语言列表，不区分大小写（默认: java）。例如：--languages java 或 --languages Java Go",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    main(
        top_n=args.top_n,
        min_score=args.min_score,
        exclude_merge_commits=not args.include_merge,
        programming_languages=args.languages,
    )
