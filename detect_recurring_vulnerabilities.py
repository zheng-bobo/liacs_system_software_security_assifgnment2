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

For details, please refer to README.md
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
import json

# 尝试导入 javalang，如果失败则使用正则表达式方法
try:
    import javalang
    import javalang.parser
    import javalang.tree
    import javalang.tokenizer

    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False
    # 此时 logger 还未初始化，使用 print 或稍后在 logger 初始化后记录


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

# 如果 javalang 不可用，记录警告信息
if not JAVALANG_AVAILABLE:
    logger.warning(
        "javalang 未安装，normalize_identifiers 将使用正则表达式方法。"
        "要使用更准确的 Java parser，请运行: pip install javalang"
    )


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


class CodeSimilarityMatcher:
    """
    多层次代码相似性匹配类

    实现5种不同的代码表示方法：
    1. 原始文本（Raw text）
    2. 去空格/去缩进文本（Whitespace-normalized text）
    3. 变量名标准化（Identifier-normalized text）
    4. Token Shingles（用于 MinHash/LSH）
    5. AST 表示/子树哈希（AST subtree hashing）
    """

    def __init__(self, shingle_size: int = 5, use_ast: bool = False):
        """
        初始化相似性匹配器

        Args:
            shingle_size: Token shingle 的大小，默认 5
            use_ast: 是否使用 AST 分析，默认 False
        """
        self.shingle_size = shingle_size
        self.use_ast = use_ast
        # 标识符归一化计数器
        self.var_counter = 0
        self.func_counter = 0
        self.class_counter = 0

    def extract_whitespace_normalized(
        self, code: str, preserve_newlines: bool = False
    ) -> str:
        """
        2. 去空格/去缩进文本：去除所有缩进，统一空格数量

        Args:
            code: 原始代码
            preserve_newlines: 是否保留换行符，默认 False（用空格连接）

        Returns:
            标准化空白字符后的代码
        """
        if not code:
            return ""

        # 去除所有行首空白字符
        lines = [line.lstrip() for line in code.split("\n")]
        # 去除空行
        lines = [line for line in lines if line.strip()]
        # 统一空格：多个连续空格替换为单个空格
        normalized_lines = [re.sub(r"\s+", " ", line) for line in lines]

        # 根据参数决定是否保留换行符
        if preserve_newlines:
            return "\n".join(normalized_lines)
        else:
            return " ".join(normalized_lines)

    def extract_identifier_normalized(self, code: str, language: str = "java") -> str:
        """
        3. 变量名标准化：将局部变量名替换成统一占位符

        先进行空白字符标准化（保留换行），再进行标识符归一化。

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            变量名标准化后的代码
        """
        if not code:
            return ""

        # 先进行空白字符标准化（保留换行，但统一空格和去除缩进）
        whitespace_normalized = self.extract_whitespace_normalized(
            code, preserve_newlines=True
        )

        # 再进行标识符归一化
        return self._normalize_identifiers(whitespace_normalized, language)

    def extract_token_shingles(self, code: str, language: str = "java") -> List[str]:
        """
        4. Token Shingles：将代码切分成 token，再组成固定长度的 shingles

        流程：原始代码 → 空白字符标准化 → 标准化变量名（VAR1, VAR2…） → Token 化 → 生成 shingles

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            Token shingles 列表
        """
        if not code:
            return []

        # 步骤1: 先进行空白字符标准化（保留换行，但统一空格和去除缩进）
        whitespace_normalized = self.extract_whitespace_normalized(
            code, preserve_newlines=True
        )

        # 步骤2: 再进行变量名标准化（VAR1, VAR2...）
        normalized_code = self._normalize_identifiers(whitespace_normalized, language)

        # 步骤3: Token 化 - 按空白字符和标点符号分割，保留关键字和标识符
        tokens = re.findall(r"\b\w+\b|[^\w\s]", normalized_code)

        # 步骤4: 生成 shingles
        shingles = []
        for i in range(len(tokens) - self.shingle_size + 1):
            shingle = " ".join(tokens[i : i + self.shingle_size])
            shingles.append(shingle)

        return shingles

    def _normalize_identifiers(self, code: str, language: str = "java") -> str:
        """
        统一命名格式：变量名 → VAR_x，方法名 → FUNC_x，类名 → CLASS_x

        优先使用语言特定 parser（更准确），如果不可用则回退到正则表达式方法。

        Args:
            code: 预处理后的代码
            language: 编程语言类型，默认 'java'

        Returns:
            标识符归一化后的代码
        """
        language_lower = language.lower()

        # Java: 使用 javalang parser（如果可用）
        if language_lower == "java" and JAVALANG_AVAILABLE:
            try:
                return self._normalize_identifiers_with_parser(code)
            except Exception as e:
                logger.warning(f"使用 Java parser 失败，回退到正则表达式方法: {e}")
                return self._normalize_identifiers_with_regex(code, language)

        # 其他语言或 parser 不可用：使用正则表达式方法
        return self._normalize_identifiers_with_regex(code, language)

    def _normalize_identifiers_with_parser(self, code: str) -> str:
        """
        使用 javalang parser 进行标识符归一化（更准确的方法）

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
        param_map = {}

        try:
            # 解析 Java 代码
            tree = javalang.parse.parse(code)
        except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
            # 如果代码片段不完整，尝试包装成类
            try:
                wrapped_code = f"class TempClass {{\n{code}\n}}"
                tree = javalang.parse.parse(wrapped_code)
            except Exception:
                # 如果还是失败，回退到正则表达式
                return self._normalize_identifiers_with_regex(code, "java")

        # 遍历 AST 收集类名
        for path, node in tree.filter(javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name not in class_map:
                class_map[class_name] = f"CLASS_{self.class_counter}"
                self.class_counter += 1

        # 遍历 AST 收集方法名和参数
        for path, node in tree.filter(javalang.tree.MethodDeclaration):
            method_name = node.name
            if method_name not in func_map:
                func_map[method_name] = f"FUNC_{self.func_counter}"
                self.func_counter += 1

            # 收集方法参数
            if node.parameters:
                for param in node.parameters:
                    param_name = param.name
                    if param_name not in param_map:
                        param_map[param_name] = f"VAR_{self.var_counter}"
                        self.var_counter += 1

        # 遍历 AST 收集变量声明（包括局部变量和字段）
        for path, node in tree.filter(javalang.tree.VariableDeclarator):
            var_name = node.name
            if var_name not in var_map:
                var_map[var_name] = f"VAR_{self.var_counter}"
                self.var_counter += 1

        # 合并所有映射，按长度从长到短排序，避免短标识符误替换长标识符的一部分
        all_identifiers = {**var_map, **param_map, **func_map, **class_map}

        # 使用标识符名称进行替换，按长度从长到短排序
        result = code
        for original, normalized in sorted(
            all_identifiers.items(), key=lambda x: -len(x[0])
        ):
            # 使用单词边界确保精确匹配，避免误替换
            pattern = r"\b" + re.escape(original) + r"\b"
            result = re.sub(pattern, normalized, result)

        # 统一字面量：数字 → NUM，字符串 → STR
        result = re.sub(r"\b\d+\.?\d*\b", "NUM", result)
        result = re.sub(r'"[^"]*"', "STR", result)
        result = re.sub(r"'[^']*'", "STR", result)

        return result

    def _normalize_identifiers_with_regex(
        self, code: str, language: str = "java"
    ) -> str:
        """
        使用正则表达式进行标识符归一化（仅支持 Java）

        Args:
            code: 预处理后的代码
            language: 编程语言类型，默认 'java'（目前仅支持 Java）

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

        # Java 变量声明：类型 变量名 = ...
        var_pattern = r"\b(int|String|boolean|long|double|float|char|byte|short|Object|List|Map|Set)\s+(\w+)\s*[=;]"
        # Java 方法声明
        func_pattern = r"\b(public|private|protected)?\s*(static)?\s*\w+\s+(\w+)\s*\("
        # Java 类声明
        class_pattern = r"\bclass\s+(\w+)"

        # 识别并替换变量名
        for match in re.finditer(var_pattern, code):
            var_name = match.group(2)
            if var_name not in var_map:
                var_map[var_name] = f"VAR_{self.var_counter}"
                self.var_counter += 1
            code = code.replace(var_name, var_map[var_name])

        # 识别并替换方法名
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

    def _ast_to_json(self, node) -> Dict:
        """
        将 javalang AST 节点转换为 JSON 字典

        Args:
            node: javalang AST 节点

        Returns:
            AST 节点的 JSON 表示
        """
        if node is None:
            return None

        node_type = type(node).__name__
        result = {"type": node_type}

        # 使用 __dict__ 获取节点的属性（javalang AST 节点通常有 __dict__）
        if hasattr(node, "__dict__"):
            for attr_name, attr_value in node.__dict__.items():
                # 跳过私有属性
                if attr_name.startswith("_"):
                    continue

                # 跳过 None 值
                if attr_value is None:
                    continue

                # 处理列表
                if isinstance(attr_value, list):
                    if attr_value:
                        result[attr_name] = [
                            (
                                self._ast_to_json(item)
                                if (
                                    hasattr(item, "__dict__")
                                    or (
                                        JAVALANG_AVAILABLE
                                        and isinstance(item, javalang.tree.Node)
                                    )
                                )
                                else item
                            )
                            for item in attr_value
                        ]
                    else:
                        result[attr_name] = []
                # 处理 AST 节点（javalang.tree.Node 的子类）
                elif (
                    JAVALANG_AVAILABLE and isinstance(attr_value, javalang.tree.Node)
                ) or (
                    hasattr(attr_value, "__dict__")
                    and not isinstance(attr_value, (str, int, float, bool))
                ):
                    result[attr_name] = self._ast_to_json(attr_value)
                # 处理基本类型（字符串、数字、布尔值等）
                elif isinstance(attr_value, (str, int, float, bool)):
                    result[attr_name] = attr_value
                # 其他类型（如 Position、Token 等）
                else:
                    # 尝试转换为字符串表示
                    try:
                        result[attr_name] = str(attr_value)
                    except:
                        pass

        return result

    def extract_ast_subtree_hash(
        self, code: str, language: str = "java"
    ) -> Optional[str]:
        """
        5. AST 子树哈希：使用 parser 生成 AST 并计算子树哈希

        流程：原始代码 → 空白字符标准化 → AST 解析 → AST JSON → 生成哈希

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            AST 子树哈希值，如果解析失败返回 None
        """
        if not code or language.lower() != "java":
            return None

        if not JAVALANG_AVAILABLE:
            return None

        # 先进行空白字符标准化（保留换行，但统一空格和去除缩进）
        normalized_code = self.extract_whitespace_normalized(
            code, preserve_newlines=True
        )

        try:
            # 解析为 AST
            tree = javalang.parse.parse(normalized_code)
        except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
            try:
                # 尝试包装成类
                wrapped_code = f"class TempClass {{\n{normalized_code}\n}}"
                tree = javalang.parse.parse(wrapped_code)
            except Exception:
                return None

        # 将 AST 转换为 JSON
        ast_json = self._ast_to_json(tree)

        # 将 JSON 转换为字符串并生成哈希
        ast_json_str = json.dumps(ast_json, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(ast_json_str.encode()).hexdigest()[:16]

    def extract_keyword_tokens(self, code: str, language: str = "java") -> set:
        """
        提取关键函数 tokens（keyword set），用于 GitHub 搜索查询

        提取的关键 tokens 包括：
        - Java 关键字（if, for, while, try, catch, return 等）
        - 方法调用名
        - 类名
        - 常见 API 调用

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            关键 tokens 的集合
        """
        if not code:
            return set()

        # Java 关键字列表
        java_keywords = {
            "abstract",
            "assert",
            "boolean",
            "break",
            "byte",
            "case",
            "catch",
            "char",
            "class",
            "const",
            "continue",
            "default",
            "do",
            "double",
            "else",
            "enum",
            "extends",
            "final",
            "finally",
            "float",
            "for",
            "goto",
            "if",
            "implements",
            "import",
            "instanceof",
            "int",
            "interface",
            "long",
            "native",
            "new",
            "package",
            "private",
            "protected",
            "public",
            "return",
            "short",
            "static",
            "strictfp",
            "super",
            "switch",
            "synchronized",
            "this",
            "throw",
            "throws",
            "transient",
            "try",
            "void",
            "volatile",
            "while",
        }

        keywords = set()

        # 提取所有标识符（包括关键字、类名、方法名等）
        tokens = re.findall(r"\b\w+\b", code)

        for token in tokens:
            # 添加 Java 关键字
            if token in java_keywords:
                keywords.add(token)
            # 添加首字母大写的标识符（可能是类名）
            elif token and token[0].isupper() and len(token) > 1:
                keywords.add(token)
            # 添加常见的方法调用模式（如 getParameter, setHeader 等）
            elif re.match(r"^[a-z][a-zA-Z]*$", token) and len(token) > 2:
                # 过滤掉太短的标识符
                if len(token) >= 4:
                    keywords.add(token)

        # 如果使用 AST，可以提取更准确的方法调用和类名
        if language.lower() == "java" and JAVALANG_AVAILABLE:
            normalized_code = self.extract_whitespace_normalized(
                code, preserve_newlines=True
            )
            try:
                tree = javalang.parse.parse(normalized_code)
            except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
                try:
                    wrapped_code = f"class TempClass {{\n{normalized_code}\n}}"
                    tree = javalang.parse.parse(wrapped_code)
                except Exception:
                    return keywords

            # 提取方法调用名
            for path, node in tree.filter(javalang.tree.MethodInvocation):
                if hasattr(node, "member") and node.member:
                    keywords.add(node.member)

            # 提取类名
            for path, node in tree.filter(javalang.tree.ClassDeclaration):
                if hasattr(node, "name") and node.name:
                    keywords.add(node.name)

            # 提取方法声明名
            for path, node in tree.filter(javalang.tree.MethodDeclaration):
                if hasattr(node, "name") and node.name:
                    keywords.add(node.name)

        return keywords

    def compute_all_representations(
        self, code: str, language: str = "java"
    ) -> Dict[str, any]:
        """
        计算代码的所有表示方法

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            包含所有表示方法的字典，包括：
            - raw_text: 原始代码
            - normalized_text: 变量名标准化后的代码（用于人工检查）
            - token_shingles: Token shingles 列表（用于文本近似代码匹配）
            - ast_subtree_hash: AST 子树哈希值（用于结构匹配，最稳定）
            - keyword_tokens: 关键函数 tokens（keyword set，用于基础分组和 GitHub 搜索查询）
        """
        return {
            "raw_text": code,
            "normalized_text": self.extract_identifier_normalized(code, language),
            "token_shingles": self.extract_token_shingles(code, language),
            "ast_subtree_hash": self.extract_ast_subtree_hash(code, language),
            "keyword_tokens": self.extract_keyword_tokens(code, language),
        }

    def compute_similarity(
        self, repr1: Dict[str, any], repr2: Dict[str, any], method: str = "jaccard"
    ) -> float:
        """
        计算两个代码表示的相似度

        Args:
            repr1: 第一个代码的表示
            repr2: 第二个代码的表示
            method: 相似度计算方法 ('jaccard', 'cosine', 'exact')

        Returns:
            相似度分数 (0-1)
        """
        if method == "jaccard":
            # 使用 token shingles 的 Jaccard 相似度
            shingles1 = set(repr1.get("token_shingles", []))
            shingles2 = set(repr2.get("token_shingles", []))

            if not shingles1 and not shingles2:
                return 1.0
            if not shingles1 or not shingles2:
                return 0.0

            intersection = len(shingles1 & shingles2)
            union = len(shingles1 | shingles2)
            return intersection / union if union > 0 else 0.0

        elif method == "exact":
            # 精确匹配：比较 normalized_text 文本
            text1 = repr1.get("normalized_text", "")
            text2 = repr2.get("normalized_text", "")
            return 1.0 if text1 == text2 else 0.0

        elif method == "ast_hash":
            # AST 结构相似度
            hash1 = repr1.get("ast_subtree_hash")
            hash2 = repr2.get("ast_subtree_hash")

            if hash1 and hash2:
                return 1.0 if hash1 == hash2 else 0.0
            return 0.0

        elif method == "combined":
            # 综合多特征相似度
            return self.compute_multi_feature_similarity(repr1, repr2)["combined"]

        return 0.0

    def compute_multi_feature_similarity(
        self,
        repr1: Dict[str, any],
        repr2: Dict[str, any],
        weights: Dict[str, float] = None,
    ) -> Dict[str, float]:
        """
        计算多特征相似度

        结合以下特征：
        - Token shingles (MinHash/LSH): 文本近似代码
        - AST subtree hash: 结构匹配（最稳定）
        - Keywords: 基础分组
        - normalized_text: 人工检查

        Args:
            repr1: 第一个代码的表示
            repr2: 第二个代码的表示
            weights: 各特征的权重，默认值：
                - ast_hash: 0.4 (最稳定)
                - token_shingles: 0.3 (文本近似)
                - keywords: 0.2 (基础分组)
                - normalized_text: 0.1 (人工检查)

        Returns:
            包含各项相似度和综合相似度的字典
        """
        if weights is None:
            weights = {
                "ast_hash": 0.4,
                "token_shingles": 0.3,
                "keywords": 0.2,
                "normalized_text": 0.1,
            }

        similarities = {}

        # 1. AST subtree hash 相似度（结构匹配，最稳定）
        ast_hash1 = repr1.get("ast_subtree_hash")
        ast_hash2 = repr2.get("ast_subtree_hash")
        if ast_hash1 and ast_hash2:
            similarities["ast_hash"] = 1.0 if ast_hash1 == ast_hash2 else 0.0
        else:
            similarities["ast_hash"] = 0.0

        # 2. Token shingles 相似度（文本近似代码）
        shingles1 = set(repr1.get("token_shingles", []))
        shingles2 = set(repr2.get("token_shingles", []))
        if shingles1 and shingles2:
            intersection = len(shingles1 & shingles2)
            union = len(shingles1 | shingles2)
            similarities["token_shingles"] = intersection / union if union > 0 else 0.0
        elif not shingles1 and not shingles2:
            similarities["token_shingles"] = 1.0
        else:
            similarities["token_shingles"] = 0.0

        # 3. Keywords 相似度（基础分组）
        keywords1 = repr1.get("keyword_tokens", set())
        keywords2 = repr2.get("keyword_tokens", set())
        if keywords1 and keywords2:
            intersection = len(keywords1 & keywords2)
            union = len(keywords1 | keywords2)
            similarities["keywords"] = intersection / union if union > 0 else 0.0
        elif not keywords1 and not keywords2:
            similarities["keywords"] = 1.0
        else:
            similarities["keywords"] = 0.0

        # 4. Normalized text 相似度（人工检查）
        normalized1 = repr1.get("normalized_text", "")
        normalized2 = repr2.get("normalized_text", "")
        if normalized1 and normalized2:
            similarities["normalized_text"] = 1.0 if normalized1 == normalized2 else 0.0
        elif not normalized1 and not normalized2:
            similarities["normalized_text"] = 1.0
        else:
            similarities["normalized_text"] = 0.0

        # 计算加权综合相似度
        total_weight = sum(weights.values())
        if total_weight > 0:
            similarities["combined"] = (
                sum(
                    similarities[feature] * weights.get(feature, 0.0)
                    for feature in similarities.keys()
                    if feature != "combined"
                )
                / total_weight
            )
        else:
            similarities["combined"] = 0.0

        return similarities

    def _generate_pattern_regex(self, normalized_texts: List[str]) -> str:
        """
        从多个标准化文本生成正则表达式模式

        Args:
            normalized_texts: 标准化文本列表

        Returns:
            正则表达式字符串
        """
        if not normalized_texts:
            return ""

        # 找到共同的部分
        # 简化实现：使用第一个文本作为基础，将 VAR1, VAR2 等替换为通配符
        base_text = normalized_texts[0]

        # 先将 VAR1, VAR2, FUNC1 等替换为占位符
        # 使用特殊标记来标识需要替换的位置
        placeholders = {}
        placeholder_counter = 0

        def replace_placeholder(match):
            nonlocal placeholder_counter
            placeholder = f"__PLACEHOLDER_{placeholder_counter}__"
            placeholder_counter += 1
            placeholders[placeholder] = "(.*?)"
            return placeholder

        # 将 VAR1, VAR2, FUNC1 等替换为占位符
        regex_pattern = re.sub(
            r"\b(VAR|FUNC|CLASS|NUM|STR)\d+\b", replace_placeholder, base_text
        )

        # 转义特殊字符
        regex_pattern = re.escape(regex_pattern)

        # 恢复占位符为 (.*?)
        for placeholder, replacement in placeholders.items():
            escaped_placeholder = re.escape(placeholder)
            regex_pattern = regex_pattern.replace(escaped_placeholder, replacement)

        return regex_pattern

    def create_pattern_records(
        self,
        similarity_groups: List[List[int]],
        representations: List[Dict],
        df: pd.DataFrame,
        language: str = "java",
    ) -> pd.DataFrame:
        """
        为每个相似模式组创建模式记录（Pattern Record）

        Args:
            similarity_groups: 相似模式组列表，每个组包含相似的代码索引
            representations: 代码表示列表
            df: 原始 DataFrame
            language: 编程语言

        Returns:
            包含模式记录的 DataFrame
        """
        pattern_records = []
        pattern_counter = 0

        for group_indices in similarity_groups:
            if len(group_indices) < 2:
                continue  # 至少需要2个相似样本才能形成模式

            pattern_counter += 1
            pattern_id = f"p{pattern_counter:03d}"

            # 收集组内所有代码的标准化文本
            normalized_texts = []
            keyword_tokens_set = set()
            ast_hashes = []
            cves = []
            snippets = []

            for idx in group_indices:
                repr = representations[idx]["repr"]
                row = df.iloc[idx]

                # 收集标准化文本
                normalized_text = repr.get("normalized_text", "")
                if normalized_text:
                    normalized_texts.append(normalized_text)

                # 合并 keyword_tokens
                keyword_tokens_set.update(repr.get("keyword_tokens", set()))

                # 收集 AST hash
                ast_hash = repr.get("ast_subtree_hash")
                if ast_hash:
                    ast_hashes.append(ast_hash)

                # 收集 CVE
                cve = row.get("cve_id", "")
                if cve:
                    cves.append(str(cve))

                # 收集代码片段
                code_before = row.get("code_before", "")
                if code_before:
                    snippets.append(str(code_before)[:500])

            # 生成正则表达式
            regex_pattern = self._generate_pattern_regex(normalized_texts)

            # 选择最常见的 AST hash
            ast_hash = Counter(ast_hashes).most_common(1)[0][0] if ast_hashes else None

            # 选择第一个标准化文本和代码片段作为代表
            normalized_pattern_text = normalized_texts[0] if normalized_texts else ""
            example_snippet = snippets[0] if snippets else ""

            pattern_records.append(
                {
                    "pattern_id": pattern_id,
                    "language": language,
                    "normalized_pattern_text": normalized_pattern_text[:1000],
                    "keyword_tokens": sorted(list(keyword_tokens_set)),
                    "regex": regex_pattern[:500],
                    "ast_hash": ast_hash,
                    "example_cves": sorted(list(set(cves))),
                    "example_snippet": example_snippet,
                    "pattern_count": len(group_indices),  # 该模式出现的次数
                }
            )

        return pd.DataFrame(pattern_records)

    def find_similar_fixes(
        self,
        df: pd.DataFrame,
        top_n: int = 10,
        similarity_threshold: float = 0.5,
        similarity_method: str = "combined",
        use_keyword_grouping: bool = True,
        create_patterns: bool = True,
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        从 DataFrame 中找出相似的漏洞代码模式，结合多种特征

        使用 code_before（漏洞代码）进行模式匹配，用于漏洞模式挖掘。

        使用的特征：
        - Token shingles (MinHash/LSH): 文本近似代码
        - AST subtree hash: 结构匹配（最稳定）
        - Keywords: 基础分组
        - normalized_text: 人工检查

        Args:
            df: 包含 code_before, code_after, code_diff 的 DataFrame
            top_n: 返回前 n 个最相似的漏洞模式
            similarity_threshold: 相似度阈值，默认 0.5
            similarity_method: 相似度计算方法，默认 'combined'
            use_keyword_grouping: 是否使用 keywords 进行预分组以提高效率，默认 True
            create_patterns: 是否创建模式记录，默认 True

        Returns:
            (相似漏洞对 DataFrame, 模式记录 DataFrame)
        """
        logger.info("开始计算代码表示（使用漏洞代码 code_before）...")

        # 计算所有漏洞代码的表示
        representations = []
        for idx, row in df.iterrows():
            code_before = str(row.get("code_before", ""))
            language = str(row.get("programming_language", "java")).lower()

            # 只计算漏洞代码的表示（用于模式匹配）
            repr_before = self.compute_all_representations(code_before, language)

            representations.append(
                {
                    "index": idx,
                    "repr": repr_before,  # 简化字段名
                    "row": row,
                    "language": language,
                }
            )

        logger.info(f"计算了 {len(representations)} 个代码表示")

        # 如果使用 keyword 分组，先按 keywords 分组
        if use_keyword_grouping and similarity_method == "combined":
            logger.info("使用 keywords 进行预分组...")
            keyword_groups = {}
            for i, repr_data in enumerate(representations):
                keywords = frozenset(repr_data["repr"].get("keyword_tokens", set()))
                keyword_groups.setdefault(keywords, []).append(i)
            logger.info(f"Keywords 分组后得到 {len(keyword_groups)} 个组")
        else:
            keyword_groups = {None: list(range(len(representations)))}

        logger.info("开始计算相似度...")

        # 计算相似度矩阵
        similarity_scores = []
        compared_pairs = 0

        for group_indices in keyword_groups.values():
            for i_idx, i in enumerate(group_indices):
                for j in group_indices[i_idx + 1 :]:
                    repr1 = representations[i]["repr"]
                    repr2 = representations[j]["repr"]

                    # 根据 similarity_method 选择计算方法
                    if similarity_method == "combined":
                        similarity = self.compute_multi_feature_similarity(
                            repr1, repr2
                        )["combined"]
                    else:
                        similarity = self.compute_similarity(
                            repr1, repr2, similarity_method
                        )

                    compared_pairs += 1

                    if similarity >= similarity_threshold:
                        row_i, row_j = df.iloc[i], df.iloc[j]
                        similarity_scores.append(
                            {
                                "fix1_index": i,
                                "fix2_index": j,
                                "similarity": similarity,
                                "fix1_hash": row_i.get("hash", ""),
                                "fix2_hash": row_j.get("hash", ""),
                                "fix1_cve": row_i.get("cve_id", ""),
                                "fix2_cve": row_j.get("cve_id", ""),
                            }
                        )

        logger.info(f"比较了 {compared_pairs} 对代码")
        logger.info(f"找到 {len(similarity_scores)} 对相似的漏洞模式")

        # 按相似度排序并选择 top n
        similarity_df = pd.DataFrame(similarity_scores)
        if len(similarity_df) == 0:
            logger.warning("未找到相似的漏洞模式")
            return pd.DataFrame(), pd.DataFrame()

        top_similar = similarity_df.sort_values("similarity", ascending=False).head(
            top_n
        )

        # 添加详细信息
        result_rows = []
        for _, sim_row in top_similar.iterrows():
            idx1, idx2 = int(sim_row["fix1_index"]), int(sim_row["fix2_index"])
            row1, row2 = df.iloc[idx1], df.iloc[idx2]
            repr1, repr2 = representations[idx1]["repr"], representations[idx2]["repr"]

            result_rows.append(
                {
                    "similarity": sim_row["similarity"],
                    "fix1_hash": sim_row["fix1_hash"],
                    "fix1_cve": sim_row["fix1_cve"],
                    "fix1_repo": row1.get("repo_url", ""),
                    "fix1_code_before": row1.get("code_before", "")[:200],
                    "fix1_code_after": row1.get("code_after", "")[:200],
                    "fix1_normalized": repr1.get("normalized_text", "")[:200],
                    "fix2_hash": sim_row["fix2_hash"],
                    "fix2_cve": sim_row["fix2_cve"],
                    "fix2_repo": row2.get("repo_url", ""),
                    "fix2_code_before": row2.get("code_before", "")[:200],
                    "fix2_code_after": row2.get("code_after", "")[:200],
                    "fix2_normalized": repr2.get("normalized_text", "")[:200],
                }
            )

        result_df = pd.DataFrame(result_rows)
        logger.info(f"返回前 {len(result_df)} 个最相似的漏洞模式")

        # 创建模式记录
        pattern_df = pd.DataFrame()
        if create_patterns:
            logger.info("创建模式记录...")
            # 基于 AST hash 和 normalized_text 进行分组
            pattern_groups = {}
            for idx, repr_data in enumerate(representations):
                repr = repr_data["repr"]
                ast_hash = repr.get("ast_subtree_hash")
                normalized_text = repr.get("normalized_text", "")

                # 使用 AST hash 作为主要分组键（最稳定）
                group_key = (
                    ast_hash
                    if ast_hash
                    else (
                        normalized_text[:100] if normalized_text else f"no_hash_{idx}"
                    )
                )
                pattern_groups.setdefault(group_key, []).append(idx)

            # 过滤出至少包含2个样本的组
            similarity_groups = [
                group for group in pattern_groups.values() if len(group) >= 2
            ]

            if similarity_groups:
                language = representations[0]["language"] if representations else "java"
                pattern_df = self.create_pattern_records(
                    similarity_groups, representations, df, language
                )
                logger.info(f"创建了 {len(pattern_df)} 个模式记录")

        return result_df, pattern_df


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
    similarity_method: str = "combined",
    similarity_threshold: float = 0.5,
    use_keyword_grouping: bool = True,
) -> pd.DataFrame:
    """
    步骤2: 识别重复漏洞代码模式并保存结果

    使用 CodeSimilarityMatcher 的 find_similar_fixes 方法，结合多种特征识别重复模式，
    并返回 Pattern Record 数据。

    Args:
        vulnerable_code_df: 包含漏洞代码的 DataFrame
        top_n: 返回前 n 个最常见的模式，默认 3
        output_dir: 输出目录，默认 None（使用当前目录下的 output 目录）
        similarity_method: 相似度计算方法，默认 'combined'（综合多特征）
        similarity_threshold: 相似度阈值，默认 0.5
        use_keyword_grouping: 是否使用 keywords 进行预分组以提高效率，默认 True

    Returns:
        包含 Pattern Record 的 DataFrame，包含以下字段：
        - pattern_id: 模式 ID（如 p001）
        - language: 编程语言
        - normalized_pattern_text: 标准化模式文本
        - keyword_tokens: 关键字 tokens 列表
        - regex: 正则表达式模式
        - ast_hash: AST 哈希值
        - example_cves: 示例 CVE 列表
        - example_snippet: 示例代码片段
        - pattern_count: 该模式出现的次数
    """
    logger.info("\n步骤2: 识别重复漏洞代码模式（使用 find_similar_fixes）")

    # 设置输出目录
    if output_dir is None:
        output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 使用 CodeSimilarityMatcher 的 find_similar_fixes 方法
    logger.info("使用 CodeSimilarityMatcher.find_similar_fixes 识别重复模式...")
    matcher = CodeSimilarityMatcher(shingle_size=5, use_ast=True)

    # 调用 find_similar_fixes，它会自动创建 Pattern Records
    logger.info(
        f"参数: similarity_method={similarity_method}, similarity_threshold={similarity_threshold}"
    )
    logger.info(f"use_keyword_grouping={use_keyword_grouping}, top_n={top_n}")

    similar_fixes_df, pattern_records_df = matcher.find_similar_fixes(
        vulnerable_code_df,
        top_n=top_n * 10,  # 获取更多相似对以便生成更多模式
        similarity_threshold=similarity_threshold,
        similarity_method=similarity_method,
        use_keyword_grouping=use_keyword_grouping,
        create_patterns=True,
    )

    # 如果没有生成模式记录，返回空 DataFrame
    if pattern_records_df.empty:
        logger.warning("未找到重复模式，返回空结果")
        return pd.DataFrame()

    # 按 pattern_count 降序排序，选择前 top_n 个
    pattern_records_df = pattern_records_df.sort_values(
        "pattern_count", ascending=False
    ).head(top_n)

    logger.info(f"识别出 {len(pattern_records_df)} 个 Pattern Records")
    logger.info(f"返回前 {len(pattern_records_df)} 个最常见的模式")

    # 保存 Pattern Records
    if len(pattern_records_df) > 0:
        # 准备保存的数据（处理列表类型的列）
        patterns_df_to_save = pattern_records_df.copy()

        # 处理列表类型的列
        if "keyword_tokens" in patterns_df_to_save.columns:
            patterns_df_to_save["keyword_tokens"] = patterns_df_to_save[
                "keyword_tokens"
            ].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
        if "example_cves" in patterns_df_to_save.columns:
            patterns_df_to_save["example_cves"] = patterns_df_to_save[
                "example_cves"
            ].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))

        # 保存 Pattern Records
        patterns_file = output_dir / f"pattern_records_top{top_n}.csv"
        patterns_df_to_save.to_csv(patterns_file, index=False, encoding="utf-8")
        logger.info(f"Pattern Records 已保存到: {patterns_file}")

        # 保存相似修复对（如果存在）
        if len(similar_fixes_df) > 0:
            similar_fixes_file = output_dir / f"similar_fixes_top{top_n}.csv"
            similar_fixes_df.to_csv(similar_fixes_file, index=False, encoding="utf-8")
            logger.info(f"相似修复对已保存到: {similar_fixes_file}")

        # 打印前几个 Pattern Records 的详细信息
        logger.info("\n" + "=" * 60)
        logger.info(f"前 {min(5, len(pattern_records_df))} 个 Pattern Records:")
        logger.info("=" * 60)
        for idx, (_, row) in enumerate(pattern_records_df.head(5).iterrows(), 1):
            logger.info(f"\nPattern Record #{idx}:")
            if "pattern_id" in row:
                logger.info(f"  Pattern ID: {row['pattern_id']}")
            if "pattern_count" in row:
                logger.info(f"  出现次数: {row['pattern_count']}")
            if "language" in row:
                logger.info(f"  编程语言: {row['language']}")
            if "ast_hash" in row:
                logger.info(f"  AST Hash: {row['ast_hash']}")
            if "keyword_tokens" in row:
                keywords = (
                    row["keyword_tokens"]
                    if isinstance(row["keyword_tokens"], str)
                    else (
                        ", ".join(row["keyword_tokens"])
                        if isinstance(row["keyword_tokens"], list)
                        else ""
                    )
                )
                logger.info(f"  Keywords: {keywords[:200]}...")
            if "example_cves" in row:
                cves = (
                    row["example_cves"]
                    if isinstance(row["example_cves"], str)
                    else (
                        ", ".join(row["example_cves"])
                        if isinstance(row["example_cves"], list)
                        else ""
                    )
                )
                logger.info(f"  示例 CVE: {cves[:200]}...")
            if "normalized_pattern_text" in row:
                logger.info(
                    f"  标准化模式文本 (前100字符): {str(row['normalized_pattern_text'])[:100]}..."
                )
            if "regex" in row:
                logger.info(f"  正则表达式 (前100字符): {str(row['regex'])[:100]}...")
            if "example_snippet" in row:
                logger.info(
                    f"  示例代码片段 (前100字符): {str(row['example_snippet'])[:100]}..."
                )

    return pattern_records_df


def generate_github_queries(
    pattern_records_df: pd.DataFrame, output_dir: Path = None
) -> pd.DataFrame:
    """
    为每个 Pattern Record 生成 GitHub 搜索查询语句

    对每个 pattern 生成 2-4 条 GitHub 查询，基于：
    - keyword_tokens（最重要的）
    - language
    - 关键代码片段

    Args:
        pattern_records_df: Pattern Records DataFrame
        output_dir: 输出目录，默认 None（使用当前目录下的 output 目录）

    Returns:
        包含 GitHub 查询的 DataFrame，包含以下字段：
        - pattern_id: 模式 ID
        - query_id: 查询 ID（每个模式有多个查询）
        - query_type: 查询类型（keyword_basic, keyword_language, keyword_file, code_snippet）
        - github_query: GitHub 搜索查询语句
        - description: 查询描述
    """
    logger.info("\n步骤3: 生成 GitHub 搜索查询")

    if output_dir is None:
        output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 语言到文件扩展名的映射
    language_extensions = {
        "java": "*.java",
        "javascript": "*.js",
        "typescript": "*.ts",
        "python": "*.py",
        "cpp": "*.cpp",
        "c": "*.c",
        "go": "*.go",
        "rust": "*.rs",
        "ruby": "*.rb",
        "php": "*.php",
    }

    github_queries = []

    for _, pattern_row in pattern_records_df.iterrows():
        pattern_id = pattern_row.get("pattern_id", "")
        language = pattern_row.get("language", "java").lower()
        keyword_tokens = pattern_row.get("keyword_tokens", [])
        normalized_text = pattern_row.get("normalized_pattern_text", "")
        example_snippet = pattern_row.get("example_snippet", "")

        # 处理 keyword_tokens（可能是字符串或列表）
        if isinstance(keyword_tokens, str):
            keywords = [k.strip() for k in keyword_tokens.split(",") if k.strip()]
        elif isinstance(keyword_tokens, list):
            keywords = [str(k).strip() for k in keyword_tokens if k.strip()]
        else:
            keywords = []

        # 过滤掉太短或太通用的关键字
        filtered_keywords = [
            k
            for k in keywords
            if len(k) >= 3
            and k.lower()
            not in [
                "if",
                "for",
                "while",
                "try",
                "catch",
                "return",
                "class",
                "public",
                "private",
                "static",
                "void",
                "int",
                "string",
                "boolean",
            ]
        ]

        # 如果没有足够的关键字，使用所有关键字
        if not filtered_keywords:
            filtered_keywords = keywords[:5]  # 最多使用5个关键字

        query_counter = 0

        # 查询类型1: 基础关键字查询（最重要的关键字）
        if filtered_keywords:
            query_counter += 1
            # 使用前3个最重要的关键字
            top_keywords = filtered_keywords[:3]
            query = " ".join(f'"{kw}"' for kw in top_keywords)
            github_queries.append(
                {
                    "pattern_id": pattern_id,
                    "query_id": f"{pattern_id}_q{query_counter:02d}",
                    "query_type": "keyword_basic",
                    "github_query": query,
                    "description": f"基础关键字查询: {', '.join(top_keywords)}",
                }
            )

        # 查询类型2: 关键字 + 语言
        if filtered_keywords and language:
            query_counter += 1
            top_keywords = filtered_keywords[:3]
            keyword_part = " ".join(f'"{kw}"' for kw in top_keywords)
            query = f"language:{language} {keyword_part}"
            github_queries.append(
                {
                    "pattern_id": pattern_id,
                    "query_id": f"{pattern_id}_q{query_counter:02d}",
                    "query_type": "keyword_language",
                    "github_query": query,
                    "description": f"关键字 + 语言查询: {language}, {', '.join(top_keywords)}",
                }
            )

        # 查询类型3: 关键字 + 文件扩展名
        if filtered_keywords and language in language_extensions:
            query_counter += 1
            top_keywords = filtered_keywords[:2]  # 使用2个关键字
            file_ext = language_extensions[language]
            keyword_part = " ".join(f'"{kw}"' for kw in top_keywords)
            query = f"path:{file_ext} {keyword_part}"
            github_queries.append(
                {
                    "pattern_id": pattern_id,
                    "query_id": f"{pattern_id}_q{query_counter:02d}",
                    "query_type": "keyword_file",
                    "github_query": query,
                    "description": f"关键字 + 文件类型查询: {file_ext}, {', '.join(top_keywords)}",
                }
            )

        # 查询类型4: 关键代码片段查询（如果有有意义的代码片段）
        if example_snippet and len(example_snippet.strip()) > 20:
            # 从代码片段中提取关键标识符（方法名、API调用等）
            # 提取看起来像方法调用或API的标识符
            code_keywords = re.findall(
                r"\b[a-z][a-zA-Z0-9]*\s*\(|\b[A-Z][a-zA-Z0-9]*\.[a-z][a-zA-Z0-9]*",
                example_snippet[:200],
            )
            if code_keywords:
                query_counter += 1
                # 选择最独特的代码片段（去除常见的方法名）
                unique_keywords = [
                    kw.rstrip("(").strip()
                    for kw in code_keywords[:2]
                    if kw.lower()
                    not in ["if", "for", "while", "try", "catch", "return"]
                ]
                if unique_keywords:
                    keyword_part = " ".join(f'"{kw}"' for kw in unique_keywords)
                    query = f"language:{language} {keyword_part}"
                    github_queries.append(
                        {
                            "pattern_id": pattern_id,
                            "query_id": f"{pattern_id}_q{query_counter:02d}",
                            "query_type": "code_snippet",
                            "github_query": query,
                            "description": f"代码片段查询: {', '.join(unique_keywords)}",
                        }
                    )

        # 如果查询数量少于2个，添加一个组合查询
        if query_counter < 2 and filtered_keywords:
            query_counter += 1
            # 使用所有关键字创建一个更宽泛的查询
            all_keywords = filtered_keywords[:5]
            query = " ".join(f'"{kw}"' for kw in all_keywords)
            github_queries.append(
                {
                    "pattern_id": pattern_id,
                    "query_id": f"{pattern_id}_q{query_counter:02d}",
                    "query_type": "keyword_comprehensive",
                    "github_query": query,
                    "description": f"综合关键字查询: {', '.join(all_keywords)}",
                }
            )

    github_queries_df = pd.DataFrame(github_queries)

    # 保存 GitHub 查询
    if len(github_queries_df) > 0:
        queries_file = output_dir / "github_queries.csv"
        github_queries_df.to_csv(queries_file, index=False, encoding="utf-8")
        logger.info(f"GitHub 查询已保存到: {queries_file}")

        # 按模式分组保存查询（便于查看）
        queries_by_pattern = []
        for pattern_id in github_queries_df["pattern_id"].unique():
            pattern_queries = github_queries_df[
                github_queries_df["pattern_id"] == pattern_id
            ]
            queries_by_pattern.append(
                {
                    "pattern_id": pattern_id,
                    "query_count": len(pattern_queries),
                    "queries": "\n".join(
                        [
                            f"  {row['query_type']}: {row['github_query']}"
                            for _, row in pattern_queries.iterrows()
                        ]
                    ),
                }
            )

        # 打印前几个模式的查询
        logger.info("\n" + "=" * 60)
        logger.info("GitHub 查询示例（前5个模式）:")
        logger.info("=" * 60)
        for pattern_info in queries_by_pattern[:5]:
            logger.info(
                f"\n模式 {pattern_info['pattern_id']} ({pattern_info['query_count']} 条查询):"
            )
            logger.info(pattern_info["queries"])

    return github_queries_df


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

    # 步骤2: 识别重复模式（使用 CodeSimilarityMatcher）
    recurring_patterns_df = process_recurring_patterns(
        vulnerable_code_df,
        top_n=top_n,
        output_dir=output_dir,
        similarity_method="exact",
    )

    # 步骤3: 生成 GitHub 搜索查询
    if len(recurring_patterns_df) > 0:
        github_queries_df = generate_github_queries(
            recurring_patterns_df, output_dir=output_dir
        )
        logger.info(
            f"为 {len(recurring_patterns_df)} 个模式生成了 {len(github_queries_df)} 条 GitHub 查询"
        )
    else:
        github_queries_df = pd.DataFrame()
        logger.warning("未找到模式，跳过 GitHub 查询生成")

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
