"""
GitHub 查询生成模块

根据漏洞模式生成 GitHub 搜索查询关键词，并调用 GitHub API 进行搜索。
"""

import os
import time
import logging
from typing import Dict, List, Optional
from pathlib import Path
import pandas as pd
import requests
from dotenv import load_dotenv

# 加载环境变量
load_dotenv(".env")

logger = logging.getLogger(__name__)


class GitHubQueryGenerator:
    """GitHub 查询生成器类"""

    def __init__(self, github_token: Optional[str] = None):
        """
        初始化 GitHub 查询生成器

        Args:
            github_token: GitHub Personal Access Token，如果为 None 则从环境变量 GITHUB_TOKEN 读取
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.api_base_url = "https://api.github.com"
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def _make_github_request(
        self, endpoint: str, params: Optional[Dict] = None, max_retries: int = 3
    ) -> Optional[Dict]:
        """
        发送 GitHub API 请求

        Args:
            endpoint: API 端点（相对于 base URL）
            params: 请求参数
            max_retries: 最大重试次数

        Returns:
            API 响应 JSON 字典，如果失败返回 None
        """
        url = f"{self.api_base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
        }

        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, params=params, timeout=30)

                # 更新 rate limit 信息
                self.rate_limit_remaining = int(
                    response.headers.get("X-RateLimit-Remaining", 0)
                )
                self.rate_limit_reset = int(
                    response.headers.get("X-RateLimit-Reset", 0)
                )

                # 处理 rate limit
                if response.status_code == 403 and self.rate_limit_remaining == 0:
                    reset_time = self.rate_limit_reset
                    wait_time = max(0, reset_time - int(time.time())) + 1
                    print(
                        f"Rate limit exceeded. Waiting {wait_time} seconds until reset..."
                    )
                    time.sleep(wait_time)
                    continue

                # 处理其他错误
                if response.status_code != 200:
                    print(
                        f"GitHub API error: {response.status_code} - {response.text[:200]}"
                    )
                    if response.status_code == 422:
                        # 422 Unprocessable Entity - 通常是查询语法错误
                        return None
                    if attempt < max_retries - 1:
                        time.sleep(2**attempt)  # 指数退避
                        continue
                    return None

                return response.json()

            except requests.exceptions.RequestException as e:
                print(f"Request error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                return None

        return None

    def search_github_code(
        self,
        query: str,
        language: Optional[str] = "java",
        per_page: int = 30,
        max_results: int = 100,
    ) -> List[Dict]:
        """
        使用 GitHub API 搜索代码

        Args:
            query: GitHub 搜索查询字符串
            language: 编程语言过滤，默认 'java'
            per_page: 每页结果数（最大 100）
            max_results: 最大返回结果数

        Returns:
            搜索结果列表，每个结果包含：repository, path, url, html_url 等信息
        """
        if not query or not query.strip():
            return []

        # 构建搜索查询（添加语言过滤）
        search_query = query
        if language:
            search_query = f"{query} language:{language}"

        results = []
        page = 1

        while len(results) < max_results:
            # 检查 rate limit
            if self.rate_limit_remaining is not None and self.rate_limit_remaining <= 0:
                reset_time = self.rate_limit_reset
                wait_time = max(0, reset_time - int(time.time())) + 1
                print(f"Rate limit reached. Waiting {wait_time} seconds...")
                time.sleep(wait_time)

            params = {
                "q": search_query,
                "per_page": min(per_page, 100),
                "page": page,
            }

            response_data = self._make_github_request("search/code", params=params)

            if not response_data:
                break

            items = response_data.get("items", [])
            if not items:
                break

            # 提取需要的信息
            for item in items:
                results.append(
                    {
                        "repository": item.get("repository", {}).get("full_name", ""),
                        "repository_url": item.get("repository", {}).get(
                            "html_url", ""
                        ),
                        "path": item.get("path", ""),
                        "url": item.get("url", ""),
                        "html_url": item.get("html_url", ""),
                        "sha": item.get("sha", ""),
                    }
                )

                if len(results) >= max_results:
                    break

            # 检查是否还有更多页面
            total_count = response_data.get("total_count", 0)
            if len(results) >= total_count or len(items) < per_page:
                break

            page += 1
            time.sleep(1)  # 避免请求过快

        return results

    def _generate_github_search_keywords(
        self,
        pattern: Dict,
        cwe_id: str,
    ) -> str:
        """
        步骤2.7: 生成 GitHub 搜索关键词

        Args:
            pattern: 漏洞模式字典
            cwe_id: CWE 编号

        Returns:
            GitHub 搜索查询字符串
        """
        keywords = []

        # Source 关键词
        source_keywords = []
        for source in pattern.get("sources", []):
            var = source.get("variable", "")
            if "getParameter" in str(source.get("pattern", "")):
                source_keywords.append("getParameter")
            elif "getHeader" in str(source.get("pattern", "")):
                source_keywords.append("getHeader")
            elif "readObject" in str(source.get("pattern", "")):
                source_keywords.append("readObject")
            elif "new File" in str(source.get("pattern", "")):
                source_keywords.append("new File")

        if source_keywords:
            keywords.append(f"({' OR '.join(set(source_keywords))})")

        # Sink 关键词（根据 CWE 类型优化）
        sink_keywords = []
        for sink in pattern.get("sinks", []):
            sink_pattern = str(sink.get("pattern", ""))
            sink_name = sink.get("sink_name", "")
            vuln_type = sink.get("vuln_type", "")

            # 根据 CWE 类型和 sink 类型添加关键词
            if cwe_id == "CWE-79":  # XSS
                if (
                    "println" in sink_pattern
                    or "print" in sink_pattern
                    or sink_name in ["println", "print", "write", "append", "getWriter"]
                ):
                    sink_keywords.append("println")
                    sink_keywords.append("response.getWriter")
                elif "innerHTML" in sink_pattern or "outerHTML" in sink_pattern:
                    sink_keywords.append("innerHTML")
            elif cwe_id == "CWE-22":  # Path Traversal
                if "File" in sink_pattern or sink_name in [
                    "new File",
                    "FileInputStream",
                    "FileOutputStream",
                ]:
                    sink_keywords.append("new File")
                elif (
                    "readAllBytes" in sink_pattern
                    or "readString" in sink_pattern
                    or sink_name in ["Files.readAllBytes", "Files.readString"]
                ):
                    sink_keywords.append("Files.readAllBytes")
                elif "Paths.get" in sink_pattern or sink_name == "Paths.get":
                    sink_keywords.append("Paths.get")
            else:  # 通用模式
                if "execute" in sink_pattern:
                    sink_keywords.append("Statement.execute")
                elif "println" in sink_pattern or "print" in sink_pattern:
                    sink_keywords.append("println")
                elif "readAllBytes" in sink_pattern or "readString" in sink_pattern:
                    sink_keywords.append("Files.readAllBytes")
                elif "exec" in sink_pattern:
                    sink_keywords.append("Runtime.exec")
                elif "File" in sink_pattern:
                    sink_keywords.append("new File")

        if sink_keywords:
            keywords.append(f"({' OR '.join(set(sink_keywords))})")

        # Taint 操作关键词（字符串拼接）
        if pattern.get("taint_flows"):
            keywords.append('"+"')  # 字符串拼接

        # Missing Sanitizers（NOT 条件）- 根据 CWE 类型优化
        missing_sanitizers = pattern.get("missing_sanitizers", [])
        not_keywords = []

        if cwe_id == "CWE-79":  # XSS - 重点关注 HTML 转义
            if "escapeHtml" in missing_sanitizers:
                not_keywords.append("escapeHtml")
                not_keywords.append("StringEscapeUtils")
                not_keywords.append("ESAPI")
        elif cwe_id == "CWE-22":  # Path Traversal - 重点关注路径规范化
            if "normalize" in missing_sanitizers:
                not_keywords.append("normalize")
                not_keywords.append("getCanonicalPath")
            if "pathValidation" in missing_sanitizers:
                not_keywords.append("isValidPath")
                not_keywords.append("PathValidator")
        else:  # 通用模式
            if "PreparedStatement" in missing_sanitizers:
                not_keywords.append("PreparedStatement")
            if "escapeHtml" in missing_sanitizers:
                not_keywords.append("escapeHtml")
            if "normalize" in missing_sanitizers:
                not_keywords.append("normalize")

        query = " AND ".join(keywords) if keywords else ""
        if not_keywords:
            query += " NOT " + " NOT ".join(not_keywords)

        return query

    def generate_github_search_keywords(
        self,
        patterns_df: pd.DataFrame,
        output_dir: Optional[Path] = None,
        top_n: Optional[int] = None,
        save_file: bool = True,
    ) -> pd.DataFrame:
        """
        为 DataFrame 中的每个模式生成 GitHub 搜索查询

        Args:
            patterns_df: 包含漏洞模式的 DataFrame，必须包含 'pattern_dict' 和 'cwe_id' 列
            output_dir: 输出目录，默认 None（使用当前目录下的 output 目录）
            top_n: top_n 值，用于生成文件名，默认 None
            save_file: 是否保存文件，默认 True

        Returns:
            更新后的 DataFrame，包含 'github_query' 列，并删除 'pattern_dict' 列
        """
        # 检查 DataFrame 是否为空
        if patterns_df.empty:
            logger.warning("patterns_df 为空，无法生成 GitHub 查询")
            return patterns_df

        # 检查必需的列是否存在
        if "pattern_dict" not in patterns_df.columns:
            logger.warning("patterns_df 缺少 'pattern_dict' 列")
        if "cwe_id" not in patterns_df.columns:
            logger.warning("patterns_df 缺少 'cwe_id' 列")

        # 为每个模式生成 GitHub 查询
        github_queries = []
        for _, row in patterns_df.iterrows():
            pattern_dict = row.get("pattern_dict")
            cwe_id = row.get("cwe_id")
            if pattern_dict and cwe_id:
                query = self._generate_github_search_keywords(pattern_dict, cwe_id)
                github_queries.append(query)
            else:
                github_queries.append("")

        # 添加 github_query 列
        result_df = patterns_df.copy()
        result_df["github_query"] = github_queries

        # 删除临时的 pattern_dict 列（如果存在）
        if "pattern_dict" in result_df.columns:
            result_df = result_df.drop(columns=["pattern_dict"])

        # 保存文件
        if save_file:
            if output_dir is None:
                output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)

            if top_n is not None:
                output_file = output_dir / f"cwe_based_patterns_top{top_n}.csv"
            else:
                output_file = output_dir / "cwe_based_patterns.csv"

            result_df.to_csv(output_file, index=False, encoding="utf-8")
            logger.info(f"已更新模式记录文件（包含 GitHub 查询）: {output_file}")

        return result_df

    def search_github_with_queries(
        self,
        patterns_df: pd.DataFrame,
        language: Optional[str] = "java",
        max_results_per_query: int = 100,
        save_results: bool = True,
        output_dir: Optional[str] = None,
    ) -> pd.DataFrame:
        """
        使用生成的 GitHub 查询调用 GitHub API 进行搜索

        Args:
            patterns_df: 包含 'github_query' 列的 DataFrame
            language: 编程语言过滤，默认 'java'
            max_results_per_query: 每个查询的最大结果数
            save_results: 是否保存搜索结果到文件
            output_dir: 输出目录，默认 None（使用当前目录）

        Returns:
            包含搜索结果的 DataFrame，新增列：
            - github_search_results: 搜索结果列表（JSON 字符串）
            - github_result_count: 结果数量
        """
        if "github_query" not in patterns_df.columns:
            raise ValueError("DataFrame must contain 'github_query' column")

        results_list = []
        result_counts = []

        total_queries = len(patterns_df)
        print(f"\n开始调用 GitHub API 搜索 {total_queries} 个查询...")

        for idx, row in patterns_df.iterrows():
            query = row.get("github_query", "")
            cwe_id = row.get("cwe_id", "")
            cve_id = row.get("cve_id", "")

            print(
                f"\n[{idx + 1}/{total_queries}] 搜索查询: {query[:100]}..."
                f" (CWE: {cwe_id}, CVE: {cve_id})"
            )

            if not query or not query.strip():
                results_list.append("[]")
                result_counts.append(0)
                continue

            # 调用 GitHub API 搜索
            search_results = self.search_github_code(
                query=query,
                language=language,
                max_results=max_results_per_query,
            )

            # 保存结果
            import json

            results_json = json.dumps(search_results, ensure_ascii=False)
            results_list.append(results_json)
            result_counts.append(len(search_results))

            print(f"  找到 {len(search_results)} 个结果")

            # 显示 rate limit 信息
            if self.rate_limit_remaining is not None:
                print(f"  Rate limit remaining: {self.rate_limit_remaining}")

            # 避免请求过快
            time.sleep(1)

        # 添加结果列
        result_df = patterns_df.copy()
        result_df["github_search_results"] = results_list
        result_df["github_result_count"] = result_counts

        # 保存结果
        if save_results:
            if output_dir is None:
                output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)

            output_file = os.path.join(output_dir, "github_search_results.csv")
            result_df.to_csv(output_file, index=False, encoding="utf-8")
            print(f"\n搜索结果已保存到: {output_file}")

        total_results = sum(result_counts)
        print(f"\n搜索完成！总共找到 {total_results} 个结果")

        return result_df
