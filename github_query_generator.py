"""
GitHub Query Generation Module

阶段 4：为每个模式生成 GitHub 搜索语句（Query Generation）
阶段 5：GitHub 搜索候选漏洞（Vulnerable Candidate Collection）

为每个漏洞模式生成多条 GitHub 搜索查询，包括：
- 基础关键字搜索
- TF-IDF 中频危险 Tokens 查询
- 正则表达式查询
- 路径过滤查询

并执行 GitHub Code Search API 搜索，收集候选漏洞代码。
"""

import re
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

    def search_github_code(
        self,
        github_queries_df: pd.DataFrame,
        github_token: Optional[str] = None,
        max_results_per_query: int = 100,
        output_dir: Path = None,
    ) -> pd.DataFrame:
        """
        阶段 5：GitHub 搜索候选漏洞（Vulnerable Candidate Collection）

        Step 7：运行 GitHub Code Search API

        为每条查询执行 GitHub Code Search API 搜索，收集候选漏洞代码。

        Args:
            github_queries_df: GitHub 查询 DataFrame（包含 query_id 和 github_query）
            github_token: GitHub Personal Access Token（如果为 None，从环境变量 GITHUB_TOKEN 读取）
            max_results_per_query: 每个查询最多返回的结果数，默认 100
            output_dir: 输出目录，默认 None（使用当前目录下的 output 目录）

        Returns:
            包含搜索结果的 DataFrame，包含以下字段：
            - repo: owner/repo
            - file_path: 文件路径（如 src/app.js）
            - fragment: 匹配代码段
            - url: GitHub URL
            - query_id: 查询 ID（如 p001_q01）
            - pattern_id: 模式 ID（如 p001）
        """
        logger.info("\n阶段 5: GitHub 搜索候选漏洞（Vulnerable Candidate Collection）")
        logger.info("Step 7: 运行 GitHub Code Search API...")

        if output_dir is None:
            output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # 获取 GitHub Token
        if github_token is None:
            github_token = os.getenv("GITHUB_TOKEN")
            if not github_token:
                logger.warning(
                    "未找到 GITHUB_TOKEN 环境变量，GitHub API 调用可能失败。"
                    "请设置环境变量或传入 github_token 参数。"
                )

        if not github_token:
            logger.error("无法执行 GitHub 搜索：缺少 GitHub Token")
            return pd.DataFrame()

        # 创建带重试机制的 requests session
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)

        # GitHub API 配置
        api_base_url = "https://api.github.com"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        search_results = []
        total_queries = len(github_queries_df)
        query_count = 0

        for idx, query_row in github_queries_df.iterrows():
            query_id = query_row.get("query_id", "")
            github_query = query_row.get("github_query", "")
            pattern_id = query_row.get("pattern_id", "")

            if not github_query:
                continue

            query_count += 1
            logger.info(
                f"[{query_count}/{total_queries}] 执行查询: {query_id} - {github_query[:60]}..."
            )

            try:
                # GitHub Code Search API
                # 注意：GitHub Code Search API 有速率限制（每分钟最多 30 次请求）
                search_url = f"{api_base_url}/search/code"
                params = {
                    "q": github_query,
                    "per_page": min(
                        100, max_results_per_query
                    ),  # GitHub API 每页最多 100 条
                }

                # 执行搜索
                response = session.get(
                    search_url, headers=headers, params=params, timeout=30
                )

                # 检查速率限制
                if response.status_code == 403:
                    rate_limit_remaining = response.headers.get(
                        "X-RateLimit-Remaining", "0"
                    )
                    rate_limit_reset = response.headers.get("X-RateLimit-Reset", "0")
                    if rate_limit_remaining == "0":
                        reset_time = int(rate_limit_reset)
                        wait_time = max(0, reset_time - int(time.time())) + 10
                        logger.warning(
                            f"GitHub API 速率限制，等待 {wait_time} 秒后重试..."
                        )
                        time.sleep(wait_time)
                        response = session.get(
                            search_url, headers=headers, params=params, timeout=30
                        )

                response.raise_for_status()
                data = response.json()

                # 处理搜索结果
                items = data.get("items", [])
                total_count = data.get("total_count", 0)

                logger.info(f"  找到 {len(items)} 个结果（总计: {total_count}）")

                # 限制结果数量
                items = items[:max_results_per_query]

                # 提取每个结果的信息
                for item in items:
                    repo_full_name = item.get("repository", {}).get("full_name", "")
                    file_path = item.get("path", "")
                    html_url = item.get("html_url", "")
                    fragment = item.get("text_matches", [{}])[0].get("fragment", "")

                    # 构建代码片段 URL（指向特定行）
                    if "line" in item.get("text_matches", [{}])[0]:
                        match_lines = item["text_matches"][0].get("matches", [])
                        if match_lines:
                            # 尝试获取匹配的行号
                            match_obj = match_lines[0]
                            if "indices" in match_obj:
                                # 可以进一步处理以获取精确行号
                                pass

                    search_results.append(
                        {
                            "repo": repo_full_name,
                            "file_path": file_path,
                            "fragment": (
                                fragment[:500] if fragment else ""
                            ),  # 限制片段长度
                            "url": html_url,
                            "query_id": query_id,
                            "pattern_id": pattern_id,
                        }
                    )

                # 处理分页（如果需要更多结果）
                # 跟踪当前查询的结果数量
                current_query_results = len(search_results)
                if total_count > len(items) and len(items) < max_results_per_query:
                    page = 2
                    while page <= 10:  # 最多 10 页
                        # 检查当前查询的结果数量是否已达到限制
                        current_query_count = (
                            len(search_results) - current_query_results
                        )
                        if current_query_count >= max_results_per_query:
                            break
                        params["page"] = page
                        response = session.get(
                            search_url, headers=headers, params=params, timeout=30
                        )

                        if response.status_code == 403:
                            rate_limit_remaining = response.headers.get(
                                "X-RateLimit-Remaining", "0"
                            )
                            if rate_limit_remaining == "0":
                                reset_time = int(
                                    response.headers.get("X-RateLimit-Reset", "0")
                                )
                                wait_time = max(0, reset_time - int(time.time())) + 10
                                logger.warning(
                                    f"GitHub API 速率限制，等待 {wait_time} 秒后重试..."
                                )
                                time.sleep(wait_time)
                                continue

                        response.raise_for_status()
                        page_data = response.json()
                        page_items = page_data.get("items", [])

                        if not page_items:
                            break

                        for item in page_items:
                            # 检查当前查询的结果数量是否已达到限制
                            current_query_count = (
                                len(search_results) - current_query_results
                            )
                            if current_query_count >= max_results_per_query:
                                break

                            repo_full_name = item.get("repository", {}).get(
                                "full_name", ""
                            )
                            file_path = item.get("path", "")
                            html_url = item.get("html_url", "")
                            fragment = item.get("text_matches", [{}])[0].get(
                                "fragment", ""
                            )

                            search_results.append(
                                {
                                    "repo": repo_full_name,
                                    "file_path": file_path,
                                    "fragment": fragment[:500] if fragment else "",
                                    "url": html_url,
                                    "query_id": query_id,
                                    "pattern_id": pattern_id,
                                }
                            )

                        # 如果当前页没有结果或已达到限制，退出分页循环
                        if not page_items or (
                            len(search_results) - current_query_results
                            >= max_results_per_query
                        ):
                            break

                        page += 1

                # 遵守 GitHub API 速率限制（每分钟最多 30 次请求）
                # 每次请求后等待 2 秒
                time.sleep(2)

            except requests.exceptions.RequestException as e:
                logger.error(f"查询 {query_id} 执行失败: {e}")
                continue
            except Exception as e:
                logger.error(f"处理查询 {query_id} 时出错: {e}")
                continue

        # 创建结果 DataFrame
        search_results_df = pd.DataFrame(search_results)

        # 保存搜索结果
        if len(search_results_df) > 0:
            results_file = output_dir / "github_search_results.csv"
            search_results_df.to_csv(results_file, index=False, encoding="utf-8")
            logger.info(f"\n搜索结果已保存到: {results_file}")
            logger.info(f"总计找到 {len(search_results_df)} 个候选漏洞代码片段")

            # 按查询统计
            query_stats = (
                search_results_df.groupby("query_id")
                .size()
                .reset_index(name="result_count")
                .sort_values("result_count", ascending=False)
            )

            logger.info("\n" + "=" * 60)
            logger.info("查询结果统计（前 10 个查询）:")
            logger.info("=" * 60)
            for _, stat_row in query_stats.head(10).iterrows():
                logger.info(
                    f"  {stat_row['query_id']}: {stat_row['result_count']} 个结果"
                )

            # 按模式统计
            pattern_stats = (
                search_results_df.groupby("pattern_id")
                .size()
                .reset_index(name="result_count")
                .sort_values("result_count", ascending=False)
            )

            logger.info("\n" + "=" * 60)
            logger.info("模式结果统计:")
            logger.info("=" * 60)
            for _, stat_row in pattern_stats.iterrows():
                logger.info(
                    f"  {stat_row['pattern_id']}: {stat_row['result_count']} 个结果"
                )

        else:
            logger.warning("未找到任何搜索结果")

        return search_results_df
