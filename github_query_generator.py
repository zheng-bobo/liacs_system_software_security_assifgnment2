"""
GitHub 查询生成模块

阶段 4：为每个模式生成 GitHub 搜索语句（Query Generation）

为每个漏洞模式生成多条 GitHub 搜索查询，包括：
- 基础关键字搜索
- TF-IDF 中频危险 Tokens 查询
- 正则表达式查询
- 路径过滤查询
"""

import re
import logging
from pathlib import Path
from typing import Dict, List
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

logger = logging.getLogger(__name__)


class GitHubQueryGenerator:
    """
    GitHub 查询生成器类

    阶段 4：为每个模式生成 GitHub 搜索语句（Query Generation）

    对每个模式 pXXX 生成多条 GitHub 查询语句：
    - Step 6.1 基础 Keyword 搜索
    - Step 6.2 TF-IDF 提取"中频危险 Tokens"
    - Step 6.3 正则搜索（regex query）
    - Step 6.4 可选路径过滤
    """

    def __init__(self):
        """初始化查询生成器"""
        # 语言到文件扩展名的映射
        self.language_extensions = {
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

        # 通用关键字过滤列表（太通用的关键字）
        self.generic_keywords = {
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
        }

    def extract_tfidf_dangerous_tokens(
        self,
        pattern_records_df: pd.DataFrame,
        min_tfidf: float = 0.1,
        max_tfidf: float = 0.7,
    ) -> Dict[str, List[str]]:
        """
        Step 6.2 TF-IDF 提取"中频危险 Tokens"

        使用 TF-IDF 从所有模式的 keyword_tokens 中提取中频危险 tokens。
        中频 = 既不是太常见（低 TF-IDF），也不是太罕见（高 TF-IDF）。

        Args:
            pattern_records_df: Pattern Records DataFrame
            min_tfidf: 最小 TF-IDF 阈值，默认 0.1
            max_tfidf: 最大 TF-IDF 阈值，默认 0.7

        Returns:
            字典，key 为 pattern_id，value 为中频危险 tokens 列表
        """
        try:
            # 收集所有模式的 keyword_tokens
            all_keyword_lists = []
            pattern_ids = []

            for _, row in pattern_records_df.iterrows():
                keyword_tokens = row.get("keyword_tokens", [])
                pattern_id = row.get("pattern_id", "")

                # 处理 keyword_tokens（可能是字符串或列表）
                if isinstance(keyword_tokens, str):
                    keywords = [
                        k.strip() for k in keyword_tokens.split(",") if k.strip()
                    ]
                elif isinstance(keyword_tokens, list):
                    keywords = [str(k).strip() for k in keyword_tokens if k.strip()]
                else:
                    keywords = []

                if keywords:
                    all_keyword_lists.append(" ".join(keywords))
                    pattern_ids.append(pattern_id)

            if not all_keyword_lists:
                return {}

            # 使用 TF-IDF 向量化
            vectorizer = TfidfVectorizer(
                token_pattern=r"\b\w+\b",  # 匹配单词
                max_features=1000,  # 最多保留1000个特征
                min_df=1,  # 至少出现在1个文档中
                max_df=0.9,  # 最多出现在90%的文档中
            )

            tfidf_matrix = vectorizer.fit_transform(all_keyword_lists)
            feature_names = vectorizer.get_feature_names_out()

            # 计算每个 token 的平均 TF-IDF 分数
            mean_tfidf = np.mean(tfidf_matrix.toarray(), axis=0)

            # 提取中频危险 tokens（在 min_tfidf 和 max_tfidf 之间）
            medium_freq_tokens = [
                feature_names[i]
                for i in range(len(feature_names))
                if min_tfidf <= mean_tfidf[i] <= max_tfidf
            ]

            # 为每个模式提取中频危险 tokens
            result = {}
            for idx, pattern_id in enumerate(pattern_ids):
                # 获取该模式的 TF-IDF 向量
                pattern_tfidf = tfidf_matrix[idx].toarray()[0]

                # 提取该模式中属于中频危险 tokens 的 tokens
                pattern_medium_tokens = [
                    feature_names[i]
                    for i in range(len(feature_names))
                    if (
                        feature_names[i] in medium_freq_tokens
                        and pattern_tfidf[i] > 0  # 该模式中确实包含这个 token
                    )
                ]

                result[pattern_id] = pattern_medium_tokens[:10]  # 最多返回10个

            return result

        except Exception as e:
            logger.warning(f"TF-IDF 提取失败，回退到基础关键字: {e}")
            return {}

    def _filter_keywords(self, keywords: List[str]) -> List[str]:
        """
        过滤关键字，去除太短或太通用的关键字

        Args:
            keywords: 原始关键字列表

        Returns:
            过滤后的关键字列表
        """
        filtered = [
            k
            for k in keywords
            if len(k) >= 3 and k.lower() not in self.generic_keywords
        ]

        # 如果没有足够的关键字，使用所有关键字（最多5个）
        if not filtered:
            filtered = keywords[:5]

        return filtered

    def _process_keyword_tokens(self, keyword_tokens) -> List[str]:
        """
        处理 keyword_tokens（可能是字符串或列表）

        Args:
            keyword_tokens: 关键字 tokens（字符串或列表）

        Returns:
            关键字列表
        """
        if isinstance(keyword_tokens, str):
            keywords = [k.strip() for k in keyword_tokens.split(",") if k.strip()]
        elif isinstance(keyword_tokens, list):
            keywords = [str(k).strip() for k in keyword_tokens if k.strip()]
        else:
            keywords = []

        return keywords

    def generate_queries_for_pattern(
        self,
        pattern_row: pd.Series,
        tfidf_tokens: Dict[str, List[str]],
    ) -> List[Dict]:
        """
        为单个模式生成 GitHub 查询

        Args:
            pattern_row: 模式记录行
            tfidf_tokens: TF-IDF tokens 字典

        Returns:
            查询列表
        """
        pattern_id = pattern_row.get("pattern_id", "")
        language = pattern_row.get("language", "java").lower()
        keyword_tokens = pattern_row.get("keyword_tokens", [])
        regex_pattern = pattern_row.get("regex", "")
        example_snippet = pattern_row.get("example_snippet", "")

        # 处理关键字
        keywords = self._process_keyword_tokens(keyword_tokens)
        filtered_keywords = self._filter_keywords(keywords)

        github_queries = []
        query_counter = 0

        # Step 6.1: 基础 Keyword 搜索
        if filtered_keywords:
            query_counter += 1
            top_keywords = filtered_keywords[:3]
            keyword_part = " ".join(f'"{kw}"' for kw in top_keywords)
            query = f"{keyword_part} language:{language}" if language else keyword_part
            github_queries.append(
                {
                    "pattern_id": pattern_id,
                    "query_id": f"{pattern_id}_q{query_counter:02d}",
                    "query_type": "keyword_basic",
                    "github_query": query,
                    "description": f"Step 6.1 基础 Keyword 搜索: {', '.join(top_keywords)}",
                }
            )

        # Step 6.2: TF-IDF 中频危险 Tokens（refined queries）
        if pattern_id in tfidf_tokens and tfidf_tokens[pattern_id]:
            query_counter += 1
            medium_tokens = tfidf_tokens[pattern_id][:4]  # 最多使用4个中频tokens
            if medium_tokens:
                keyword_part = " ".join(f'"{kw}"' for kw in medium_tokens)
                query = (
                    f"{keyword_part} language:{language}" if language else keyword_part
                )
                github_queries.append(
                    {
                        "pattern_id": pattern_id,
                        "query_id": f"{pattern_id}_q{query_counter:02d}",
                        "query_type": "tfidf_refined",
                        "github_query": query,
                        "description": f"Step 6.2 TF-IDF 中频危险 Tokens: {', '.join(medium_tokens)}",
                    }
                )

        # Step 6.3: 正则搜索（regex query）
        if regex_pattern and len(regex_pattern.strip()) > 10:
            query_counter += 1
            # GitHub 不支持完整的正则表达式，但可以尝试使用部分模式
            # 提取正则中的关键部分（去除通配符）
            regex_keywords = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", regex_pattern)
            if regex_keywords:
                # 过滤掉太短的关键字
                regex_keywords = [kw for kw in regex_keywords if len(kw) >= 3][:3]
                if regex_keywords:
                    keyword_part = " ".join(f'"{kw}"' for kw in regex_keywords)
                    query = (
                        f"{keyword_part} language:{language}"
                        if language
                        else keyword_part
                    )
                    github_queries.append(
                        {
                            "pattern_id": pattern_id,
                            "query_id": f"{pattern_id}_q{query_counter:02d}",
                            "query_type": "regex_based",
                            "github_query": query,
                            "description": f"Step 6.3 正则搜索（基于正则模式）: {', '.join(regex_keywords)}",
                        }
                    )

        # Step 6.4: 可选路径过滤
        if filtered_keywords and language in self.language_extensions:
            query_counter += 1
            top_keywords = filtered_keywords[:2]  # 使用2个关键字
            file_ext = self.language_extensions[language]
            keyword_part = " ".join(f'"{kw}"' for kw in top_keywords)
            query = f"path:{file_ext} {keyword_part}"
            github_queries.append(
                {
                    "pattern_id": pattern_id,
                    "query_id": f"{pattern_id}_q{query_counter:02d}",
                    "query_type": "path_filter",
                    "github_query": query,
                    "description": f"Step 6.4 路径过滤: {file_ext}, {', '.join(top_keywords)}",
                }
            )

        # 保留原有的查询类型（向后兼容）
        # 查询类型: 关键字 + 语言（如果没有生成其他查询）
        if query_counter == 0 and filtered_keywords and language:
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

        # 关键代码片段查询（如果有有意义的代码片段）
        if example_snippet and len(example_snippet.strip()) > 20:
            # 从代码片段中提取关键标识符（方法名、API调用等）
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

        return github_queries

    def generate(
        self, pattern_records_df: pd.DataFrame, output_dir: Path = None
    ) -> pd.DataFrame:
        """
        为每个模式生成 GitHub 搜索语句

        Args:
            pattern_records_df: Pattern Records DataFrame
            output_dir: 输出目录，默认 None（使用当前目录下的 output 目录）

        Returns:
            包含 GitHub 查询的 DataFrame，包含以下字段：
            - pattern_id: 模式 ID
            - query_id: 查询 ID（每个模式有多个查询）
            - query_type: 查询类型
            - github_query: GitHub 搜索查询语句
            - description: 查询描述
        """
        logger.info("\n阶段 4: 为每个模式生成 GitHub 搜索语句（Query Generation）")

        if output_dir is None:
            output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Step 6.2: 提取 TF-IDF 中频危险 tokens
        logger.info("Step 6.2: 使用 TF-IDF 提取中频危险 Tokens...")
        tfidf_tokens = self.extract_tfidf_dangerous_tokens(pattern_records_df)

        github_queries = []

        # 为每个模式生成查询
        for _, pattern_row in pattern_records_df.iterrows():
            queries = self.generate_queries_for_pattern(pattern_row, tfidf_tokens)
            github_queries.extend(queries)

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


# 向后兼容的函数接口
def generate_github_queries(
    pattern_records_df: pd.DataFrame, output_dir: Path = None
) -> pd.DataFrame:
    """
    阶段 4：为每个模式生成 GitHub 搜索语句（Query Generation）

    向后兼容的函数接口，内部使用 GitHubQueryGenerator 类。

    Args:
        pattern_records_df: Pattern Records DataFrame
        output_dir: 输出目录，默认 None（使用当前目录下的 output 目录）

    Returns:
        包含 GitHub 查询的 DataFrame
    """
    generator = GitHubQueryGenerator()
    return generator.generate(pattern_records_df, output_dir)
