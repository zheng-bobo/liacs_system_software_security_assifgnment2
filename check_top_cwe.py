"""
查看 top 3 CWE 类型和名称的脚本
"""

import sys
from pathlib import Path
from dotenv import load_dotenv
import logging
from vulnerability_pattern_miner import DatabaseConnector
import pandas as pd
from sqlalchemy import text

# 加载环境变量
load_dotenv(".env")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def check_top_cwe(
    top_n: int = 3, min_score: int = 65, programming_languages: list = None
):
    """
    查看 top n 的 CWE 类型和名称

    Args:
        top_n: 返回前 n 个最常见的 CWE，默认 3
        min_score: fixes.score 的最小值，默认 65
        programming_languages: 编程语言列表，默认 ['Java']
    """
    if programming_languages is None:
        programming_languages = ["Java"]

    logger.info("=" * 60)
    logger.info(f"查看 top {top_n} 的 CWE 类型和名称")
    logger.info(f"配置: min_score={min_score}, languages={programming_languages}")
    logger.info("=" * 60)

    # 初始化数据库连接
    db_connector = DatabaseConnector()

    # 构建语言过滤条件
    lang_conditions = []
    params = {"min_score": min_score, "top_n": top_n}
    for i, lang in enumerate(programming_languages):
        lang_conditions.append(f"LOWER(fc.programming_language) = LOWER(:lang_{i})")
        params[f"lang_{i}"] = lang

    lang_filter = " OR ".join(lang_conditions)

    # 优化后的 SQL：直接在数据库中完成 CWE 统计，避免传输大量数据
    logger.info("\n执行优化后的 SQL 查询...")
    query = f"""
    WITH good_fixes AS (
      SELECT DISTINCT f.cve_id, f.hash, f.repo_url
      FROM fixes f
      WHERE f.score >= :min_score
    ),
    single_file_fixes AS (
      SELECT 
        gf.cve_id,
        gf.hash,
        gf.repo_url
      FROM good_fixes gf
      JOIN file_change fc ON fc.hash = gf.hash
      JOIN commits c ON c.hash = gf.hash AND c.repo_url = gf.repo_url
      WHERE COALESCE(c.merge, FALSE) = FALSE
        AND COALESCE(fc.diff, '') <> ''
        AND fc.code_before IS NOT NULL 
        AND fc.code_before <> 'None'
        AND ({lang_filter})
      GROUP BY gf.cve_id, gf.hash, gf.repo_url
      HAVING COUNT(fc.file_change_id) = 1
    ),
    cwe_stats AS (
      SELECT 
        cc.cwe_id,
        c.cwe_name,
        COUNT(DISTINCT sff.cve_id) as fix_count,
        array_agg(DISTINCT sff.cve_id ORDER BY sff.cve_id) FILTER (WHERE sff.cve_id IS NOT NULL) as cve_list
      FROM single_file_fixes sff
      JOIN cwe_classification cc ON cc.cve_id = sff.cve_id
      JOIN cwe c ON c.cwe_id = cc.cwe_id
      GROUP BY cc.cwe_id, c.cwe_name
      HAVING COUNT(DISTINCT sff.cve_id) > 1
    )
    SELECT 
      cwe_id,
      cwe_name,
      fix_count,
      cve_list
    FROM cwe_stats
    ORDER BY fix_count DESC
    LIMIT :top_n;
    """

    try:
        top_cwe_df = db_connector.execute_query(query, params=params)
    except Exception as e:
        # 如果 array_agg 不支持，使用简化版本
        logger.warning(f"使用 array_agg 失败，尝试简化查询: {e}")
        query_simple = f"""
        WITH good_fixes AS (
          SELECT DISTINCT f.cve_id, f.hash, f.repo_url
          FROM fixes f
          WHERE f.score >= :min_score
        ),
        single_file_fixes AS (
          SELECT 
            gf.cve_id,
            gf.hash,
            gf.repo_url
          FROM good_fixes gf
          JOIN file_change fc ON fc.hash = gf.hash
          JOIN commits c ON c.hash = gf.hash AND c.repo_url = gf.repo_url
          WHERE COALESCE(c.merge, FALSE) = FALSE
            AND COALESCE(fc.diff, '') <> ''
            AND fc.code_before IS NOT NULL 
            AND fc.code_before <> 'None'
            AND ({lang_filter})
          GROUP BY gf.cve_id, gf.hash, gf.repo_url
          HAVING COUNT(fc.file_change_id) = 1
        ),
        cwe_stats AS (
          SELECT 
            cc.cwe_id,
            c.cwe_name,
            COUNT(DISTINCT sff.cve_id) as fix_count
          FROM single_file_fixes sff
          JOIN cwe_classification cc ON cc.cve_id = sff.cve_id
          JOIN cwe c ON c.cwe_id = cc.cwe_id
          GROUP BY cc.cwe_id, c.cwe_name
          HAVING COUNT(DISTINCT sff.cve_id) > 1
        )
        SELECT 
          cwe_id,
          cwe_name,
          fix_count
        FROM cwe_stats
        ORDER BY fix_count DESC
        LIMIT :top_n;
        """
        top_cwe_df = db_connector.execute_query(query_simple, params=params)

        # 如果没有 cve_list 列，需要单独查询
        if "cve_list" not in top_cwe_df.columns:
            logger.info("获取每个 CWE 的 CVE 示例...")
            for idx, row in top_cwe_df.iterrows():
                cve_query = f"""
                SELECT DISTINCT sff.cve_id
                FROM (
                  SELECT DISTINCT f.cve_id, f.hash, f.repo_url
                  FROM fixes f
                  WHERE f.score >= :min_score
                ) gf
                JOIN file_change fc ON fc.hash = gf.hash
                JOIN commits c ON c.hash = gf.hash AND c.repo_url = gf.repo_url
                JOIN cwe_classification cc ON cc.cve_id = gf.cve_id
                WHERE cc.cwe_id = :cwe_id
                  AND COALESCE(c.merge, FALSE) = FALSE
                  AND COALESCE(fc.diff, '') <> ''
                  AND fc.code_before IS NOT NULL 
                  AND fc.code_before <> 'None'
                  AND ({lang_filter})
                GROUP BY gf.cve_id, gf.hash, gf.repo_url
                HAVING COUNT(fc.file_change_id) = 1
                LIMIT 5
                """
                cve_params = params.copy()
                cve_params["cwe_id"] = row["cwe_id"]
                cve_df = db_connector.execute_query(cve_query, params=cve_params)
                top_cwe_df.at[idx, "cve_list"] = (
                    cve_df["cve_id"].tolist() if not cve_df.empty else []
                )

    if top_cwe_df.empty:
        logger.warning("未找到符合条件的 CWE")
        return

    logger.info(f"查询完成，找到 {len(top_cwe_df)} 个 top CWE")

    # 处理 cve_list 列，转换为字符串格式便于保存
    if "cve_list" in top_cwe_df.columns:

        def format_cve_list(cve_list):
            try:
                # 处理 None
                if cve_list is None:
                    return ""

                # 处理列表类型
                if isinstance(cve_list, list):
                    return ", ".join(str(c) for c in cve_list[:10])  # 最多显示10个

                # 处理 numpy 数组或其他数组类型
                if hasattr(cve_list, "__iter__") and not isinstance(cve_list, str):
                    try:
                        cve_list = list(cve_list)
                        return ", ".join(str(c) for c in cve_list[:10])
                    except (TypeError, ValueError):
                        pass

                # 尝试检查是否为 NaN（避免数组类型的歧义错误）
                try:
                    if pd.isna(cve_list):
                        return ""
                except (ValueError, TypeError):
                    pass  # 如果是数组类型，pd.isna 可能失败，继续处理

                # PostgreSQL array 格式（字符串形式）
                cve_str = str(cve_list)
                if cve_str.startswith("{") and cve_str.endswith("}"):
                    cve_str = cve_str[1:-1]  # 移除花括号
                cves = [c.strip() for c in cve_str.split(",") if c.strip()]
                return ", ".join(cves[:10])
            except Exception as e:
                # 如果所有方法都失败，返回字符串表示
                return str(cve_list)[:100]  # 限制长度

        top_cwe_df["cve_examples"] = top_cwe_df["cve_list"].apply(format_cve_list)
        # 删除原始的 cve_list 列（可能是数组类型，不便于保存）
        top_cwe_df = top_cwe_df.drop(columns=["cve_list"])

    # 显示结果
    logger.info("\n" + "=" * 60)
    logger.info(f"Top {len(top_cwe_df)} CWE 类型和名称:")
    logger.info("=" * 60)

    for idx, (_, row) in enumerate(top_cwe_df.iterrows(), 1):
        logger.info(f"\n#{idx} {row['cwe_id']}: {row['cwe_name']}")
        logger.info(f"   出现次数: {row['fix_count']} 个 CVE")

        if "cve_examples" in row and row["cve_examples"]:
            logger.info(f"   示例 CVE: {row['cve_examples']}")
        else:
            logger.info(f"   示例 CVE: (未获取)")

    # 保存结果到 CSV 文件
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"top_{top_n}_cwe.csv"

    # 重新排列列的顺序，使其更易读
    columns_order = ["cwe_id", "cwe_name", "fix_count"]
    if "cve_examples" in top_cwe_df.columns:
        columns_order.append("cve_examples")
    # 添加其他可能存在的列
    for col in top_cwe_df.columns:
        if col not in columns_order:
            columns_order.append(col)

    top_cwe_df_output = top_cwe_df[
        [col for col in columns_order if col in top_cwe_df.columns]
    ]
    top_cwe_df_output.to_csv(output_file, index=False, encoding="utf-8")

    logger.info("\n" + "=" * 60)
    logger.info(f"结果已保存到: {output_file}")
    logger.info("完成！")

    return top_cwe_df


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="查看 top CWE 类型和名称")
    parser.add_argument(
        "--top-n",
        type=int,
        default=3,
        help="返回前 n 个最常见的 CWE（默认: 3）",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=65,
        help="fixes.score 的最小值（默认: 65）",
    )
    parser.add_argument(
        "--languages",
        nargs="+",
        default=["java"],
        help="编程语言列表，不区分大小写（默认: java）",
    )

    args = parser.parse_args()

    check_top_cwe(
        top_n=args.top_n,
        min_score=args.min_score,
        programming_languages=args.languages,
    )
