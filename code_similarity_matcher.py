#!/usr/bin/env python3
"""
Code Similarity Matching Module

Phase 2: Code Normalization & Structural Analysis

This module implements multi-level code similarity matching, including:
- Code normalization (whitespace, identifiers)
- Token Shingle generation
- AST parsing and hashing
- Keyword extraction
- Regular expression generation
- Similarity calculation and clustering
"""

import re
import hashlib
import json
import logging
from typing import Optional, List, Dict, Tuple
from collections import Counter
import pandas as pd

# 尝试导入 javalang，如果失败则使用正则表达式方法
try:
    import javalang
    import javalang.parser
    import javalang.tree
    import javalang.tokenizer

    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False

logger = logging.getLogger(__name__)

# 如果 javalang 不可用，记录警告信息
if not JAVALANG_AVAILABLE:
    logger.warning(
        "javalang 未安装，normalize_identifiers 将使用正则表达式方法。"
        "要使用更准确的 Java parser，请运行: pip install javalang"
    )


class CodeSimilarityMatcher:
    """
    多层次代码相似性匹配类

    阶段 2：对漏洞代码进行规范化与结构分析（Normalization & Structural Analysis）

    实现8个步骤的代码表示方法：
    1. Step 4.1 原始代码（Raw code）
    2. Step 4.2 格式标准化（Whitespace normalization）
    3. Step 4.3 变量名标准化（Identifier Normalization）
    4. Step 4.4 Token 化与 Token Shingles（如 5-shingles）
    5. Step 4.5 AST 解析 → AST JSON（基于 Raw code）
    6. Step 4.6 AST 子树哈希（ast_subtree_hash）
    7. Step 4.7 提取关键函数 Token（Keyword Tokens）
    8. Step 4.8 自动生成正则表达式（Regex Candidate）

    一个漏洞片段有多种视图：
    Raw → Normalized → Tokens → AST → Subtree Hash → Keywords → Regex
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
        Step 4.2 格式标准化（Whitespace normalization）

        统一缩进、空格、去除多余换行。

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
        Step 4.3 变量名标准化（Identifier Normalization）

        将所有变量替换为：VAR1, VAR2, VAR3, ...
        减少命名差异影响。

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
        Step 4.4 Token 化与 Token Shingles（如 5-shingles）

        对标准化代码生成 token shingles，用于文本相似性（MinHash/LSH）。

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

    def extract_ast_json(self, code: str, language: str = "java") -> Optional[Dict]:
        """
        Step 4.5 AST 解析 → AST JSON（基于 Raw code）

        用真实代码构建 AST（语法树）并保存为 JSON。
        用于语义结构分析（不受变量名、格式影响）。

        Args:
            code: 原始代码（Raw code）
            language: 编程语言，默认 'java'

        Returns:
            AST JSON 字典，如果解析失败返回 None
        """
        if not code or language.lower() != "java":
            return None

        if not JAVALANG_AVAILABLE:
            return None

        # 使用原始代码构建 AST（不进行变量名标准化，保留真实结构）
        # 只进行空白字符标准化以统一格式
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
        return ast_json

    def extract_ast_subtree_hash(
        self, code: str, language: str = "java"
    ) -> Optional[str]:
        """
        Step 4.6 AST 子树哈希（ast_subtree_hash）

        对 AST 子树生成结构哈希，获得"结构指纹（structural fingerprint）"。
        用于识别结构相似漏洞。

        流程：原始代码 → 空白字符标准化 → AST 解析 → AST JSON → 生成哈希

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            AST 子树哈希值，如果解析失败返回 None
        """
        # 复用 extract_ast_json 方法获取 AST JSON
        ast_json = self.extract_ast_json(code, language)
        if ast_json is None:
            return None

        # 将 JSON 转换为字符串并生成哈希
        ast_json_str = json.dumps(ast_json, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(ast_json_str.encode()).hexdigest()[:16]

    def extract_keyword_tokens(self, code: str, language: str = "java") -> set:
        """
        Step 4.7 提取关键函数 Token（Keyword Tokens）

        提取代表漏洞的函数、API、库名，如：
        - path.join, process.cwd, eval, pickle.loads
        用于 GitHub 搜索构造。

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            关键 tokens 的集合，包括：
            - Java 关键字（if, for, while, try, catch, return 等）
            - 方法调用名
            - 类名
            - 常见 API 调用
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

    def extract_regex_candidate(self, code: str, language: str = "java") -> str:
        """
        Step 4.8 自动生成正则表达式（Regex Candidate）

        用于精确匹配结构化模式。
        基于标准化后的代码生成正则表达式候选。

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            正则表达式字符串
        """
        if not code:
            return ""

        # 先进行变量名标准化
        normalized_text = self.extract_identifier_normalized(code, language)

        # 将 VAR1, VAR2, FUNC1 等替换为通配符
        placeholders = {}
        placeholder_counter = 0

        def replace_placeholder(match):
            nonlocal placeholder_counter
            placeholder = f"__PLACEHOLDER_{placeholder_counter}__"
            placeholder_counter += 1
            placeholders[placeholder] = r"(\w+)"  # 匹配标识符
            return placeholder

        # 将 VAR1, VAR2, FUNC1, CLASS1, NUM, STR 等替换为占位符
        regex_pattern = re.sub(
            r"\b(VAR|FUNC|CLASS|NUM|STR)\d+\b", replace_placeholder, normalized_text
        )

        # 转义特殊字符（但保留占位符）
        # 先转义整个字符串
        regex_pattern = re.escape(regex_pattern)

        # 恢复占位符为正则表达式模式
        for placeholder, replacement in placeholders.items():
            escaped_placeholder = re.escape(placeholder)
            regex_pattern = regex_pattern.replace(escaped_placeholder, replacement)

        return regex_pattern

    def compute_all_representations(
        self, code: str, language: str = "java"
    ) -> Dict[str, any]:
        """
        计算代码的所有表示方法

        阶段 2：对漏洞代码进行规范化与结构分析（Normalization & Structural Analysis）

        一个漏洞片段有多种视图：
        Raw → Normalized → Tokens → AST → Subtree Hash → Keywords → Regex

        Args:
            code: 原始代码
            language: 编程语言，默认 'java'

        Returns:
            包含所有表示方法的字典，包括：
            - raw_text: Step 4.1 原始代码（Raw code）
            - whitespace_normalized: Step 4.2 格式标准化（Whitespace normalization）
            - normalized_text: Step 4.3 变量名标准化（Identifier Normalization）
            - token_shingles: Step 4.4 Token 化与 Token Shingles（如 5-shingles）
            - ast_json: Step 4.5 AST 解析 → AST JSON（基于 Raw code）
            - ast_subtree_hash: Step 4.6 AST 子树哈希（ast_subtree_hash）
            - keyword_tokens: Step 4.7 提取关键函数 Token（Keyword Tokens）
            - regex_candidate: Step 4.8 自动生成正则表达式（Regex Candidate）
        """
        return {
            "raw_text": code,  # Step 4.1
            "whitespace_normalized": self.extract_whitespace_normalized(
                code, preserve_newlines=True
            ),  # Step 4.2
            "normalized_text": self.extract_identifier_normalized(
                code, language
            ),  # Step 4.3
            "token_shingles": self.extract_token_shingles(code, language),  # Step 4.4
            "ast_json": self.extract_ast_json(code, language),  # Step 4.5
            "ast_subtree_hash": self.extract_ast_subtree_hash(
                code, language
            ),  # Step 4.6
            "keyword_tokens": self.extract_keyword_tokens(code, language),  # Step 4.7
            "regex_candidate": self.extract_regex_candidate(code, language),  # Step 4.8
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

            # 选择最常见的 AST hash 作为代表
            ast_hash = Counter(ast_hashes).most_common(1)[0][0] if ast_hashes else None

            # 选择代表样本（representative pattern）
            # 优先选择与最常见的 AST hash 对应的样本，如果没有则选择第一个
            representative_idx = 0
            if ast_hash:
                # 找到与最常见 AST hash 对应的第一个样本在 group_indices 中的位置
                for pos, idx in enumerate(group_indices):
                    repr = representations[idx]["repr"]
                    if repr.get("ast_subtree_hash") == ast_hash:
                        representative_idx = pos
                        break

            # 选择代表样本的标准化文本和代码片段
            normalized_pattern_text = (
                normalized_texts[representative_idx] if normalized_texts else ""
            )
            example_snippet = snippets[representative_idx] if snippets else ""

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
        Step 5 — 聚类（Clustering）

        结合多种特征进行漏洞模式聚类：
        - Token Shingles (MinHash/LSH): 文本相似性
        - AST subtree hash: 结构语义匹配
        - Keyword tokens: 初步分组
        - Normalized text: 人工验证

        聚类结果输出：
        → 漏洞模式（Vulnerability Patterns）
        例如：
        - p001：JavaScript Path Traversal（CWE-22）
        - p002：Python eval 注入（CWE-94）
        - p003：Insecure YAML load（CWE-20）

        每个聚类选一个代表样本（representative pattern）。

        使用 code_before（漏洞代码）进行模式匹配，用于漏洞模式挖掘。

        Args:
            df: 包含 code_before, code_after, code_diff 的 DataFrame
            top_n: 返回前 n 个最相似的漏洞模式
            similarity_threshold: 相似度阈值，默认 0.5
            similarity_method: 相似度计算方法，默认 'combined'（综合多特征）
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
