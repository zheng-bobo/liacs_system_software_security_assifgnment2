"""
查询单个 File Change 的 Fixes

查询满足以下条件的记录：
1. fixes.score >= 65
2. 排除 merge commits
3. diff 非空
4. 指定编程语言（如 Java）
5. 每个 fix（commit）只有一个 file_change

用法:
    python query_single_file_change_fixes.py --languages java --min-score 65
"""

import os
import sys
from pathlib import Path
from typing import Optional, List
import logging
import argparse
from dotenv import load_dotenv
import pandas as pd
import sqlalchemy
from sqlalchemy import text

# 加载环境变量
load_dotenv(".env")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("query_single_file_change_fixes.log"),
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


def query_single_file_change_fixes(
    db_connector: DatabaseConnector,
    min_score: int = 65,
    exclude_merge_commits: bool = True,
    programming_languages: list = None,
    require_diff: bool = True,
) -> pd.DataFrame:
    """
    查询每个 fix 只有一个 file_change 的记录

    Args:
        db_connector: 数据库连接器
        min_score: fixes.score 的最小值，默认 65
        exclude_merge_commits: 是否排除 merge commit，默认 True
        programming_languages: 编程语言列表，默认 ['Java']
        require_diff: 是否要求 diff 非空，默认 True

    Returns:
        包含漏洞代码信息的 DataFrame
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info(f"开始查询 {programming_languages} 语言的单个 file_change 的 fixes...")
    logger.info(
        f"筛选条件: min_score={min_score}, exclude_merge={exclude_merge_commits}, "
        f"require_diff={require_diff}, single_file_change_only=True"
    )

    # 构建语言过滤条件（不区分大小写匹配）
    lang_conditions = []
    for i, lang in enumerate(programming_languages):
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

    # code_before 条件：过滤掉 None 字符串和 NULL 值
    where_conditions.append("fc.code_before IS NOT NULL AND fc.code_before <> 'None'")

    # 编程语言条件（不区分大小写）
    where_conditions.append(f"({lang_filter})")

    where_clause = " AND ".join(where_conditions)

    query = f"""
    -- 查询每个 fix 只有一个 file_change 的记录
    WITH good_fixes AS (
      SELECT f.cve_id, f.hash, f.repo_url, f.score
      FROM fixes f
      WHERE f.score >= :min_score
    ),
    -- 统计每个 fix 的 file_change 数量，只保留数量为 1 的
    single_file_change_fixes AS (
      SELECT 
        gf.hash,
        gf.repo_url
      FROM good_fixes gf
      JOIN file_change fc
        ON fc.hash = gf.hash
      GROUP BY gf.hash, gf.repo_url
      HAVING COUNT(fc.file_change_id) = 1
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
    JOIN single_file_change_fixes sfcf
      ON sfcf.hash = gf.hash AND sfcf.repo_url = gf.repo_url
    JOIN commits c
      ON c.hash = gf.hash AND c.repo_url = gf.repo_url
    JOIN file_change fc
      ON fc.hash = gf.hash
    WHERE {where_clause};
    """

    df = db_connector.execute_query(query, params=params)

    logger.info(f"查询结果: {len(df)} 条记录")
    logger.info(f"涉及 {df['cve_id'].nunique()} 个 CVE")
    logger.info(f"涉及 {df['hash'].nunique()} 个 commit")
    logger.info(f"涉及 {df['repo_url'].nunique()} 个仓库")
    logger.info(f"涉及 {df['filename'].nunique()} 个文件")

    return df


def main(
    min_score: int = 65,
    exclude_merge_commits: bool = True,
    programming_languages: List[str] = None,
    require_diff: bool = True,
    output_file: str = None,
):
    """
    主函数：查询单个 file_change 的 fixes

    Args:
        min_score: fixes.score 的最小值，默认 65
        exclude_merge_commits: 是否排除 merge commit，默认 True
        programming_languages: 编程语言列表，默认 ['Java']
        require_diff: 是否要求 diff 非空，默认 True
        output_file: 输出文件路径，默认 None（自动生成）
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info("=" * 60)
    logger.info("查询单个 File Change 的 Fixes")
    logger.info(f"配置: min_score={min_score}, exclude_merge={exclude_merge_commits}")
    logger.info(f"语言: {programming_languages}")
    logger.info("=" * 60)

    # 初始化数据库连接
    db_connector = DatabaseConnector()

    # 执行查询
    result_df = query_single_file_change_fixes(
        db_connector,
        min_score=min_score,
        exclude_merge_commits=exclude_merge_commits,
        programming_languages=programming_languages,
        require_diff=require_diff,
    )

    # 保存结果
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    if output_file is None:
        lang_str = "_".join(programming_languages).lower()
        output_file = output_dir / f"single_file_change_fixes_{lang_str}_score{min_score}.csv"

    # 排除 code_before 和 code_after 列（如果文件很大）
    columns_to_save = [
        col
        for col in result_df.columns
        if col not in ["code_before", "code_after"]
    ]
    output_df = result_df[columns_to_save].copy()

    output_df.to_csv(output_file, index=False, encoding="utf-8")
    logger.info(f"结果已保存到: {output_file}")

    # 打印统计信息
    logger.info("\n" + "=" * 60)
    logger.info("统计信息:")
    logger.info(f"  总记录数: {len(result_df)}")
    logger.info(f"  唯一 CVE 数: {result_df['cve_id'].nunique()}")
    logger.info(f"  唯一 commit 数: {result_df['hash'].nunique()}")
    logger.info(f"  唯一仓库数: {result_df['repo_url'].nunique()}")
    logger.info(f"  唯一文件数: {result_df['filename'].nunique()}")
    logger.info("=" * 60)

    logger.info("\n查询完成！")


def parse_arguments():
    """
    解析命令行参数

    Returns:
        argparse.Namespace: 解析后的命令行参数对象
    """
    parser = argparse.ArgumentParser(description="查询单个 File Change 的 Fixes")
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
        default=["java"],
        help="编程语言列表，不区分大小写（默认: java）。例如：--languages java 或 --languages Java Go",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="输出文件路径（默认: output/single_file_change_fixes_{language}_score{score}.csv）",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    main(
        min_score=args.min_score,
        exclude_merge_commits=not args.include_merge,
        programming_languages=args.languages,
        require_diff=True,
        output_file=args.output,
    )

