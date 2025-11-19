"""
查询 CWE 表的数据

用法:
    python query_cwe_table.py
"""

import os
import sys
from pathlib import Path
from typing import Optional
import logging
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


def query_cwe_table(db_connector: DatabaseConnector, limit: int = None) -> pd.DataFrame:
    """
    查询 CWE 表的数据

    Args:
        db_connector: 数据库连接器
        limit: 限制返回的记录数，None 表示返回所有记录

    Returns:
        包含 CWE 信息的 DataFrame
    """
    query = "SELECT * FROM cwe ORDER BY cwe_id"
    
    if limit:
        query += f" LIMIT {limit}"
    
    df = db_connector.execute_query(query)
    
    logger.info(f"查询结果: {len(df)} 条记录")
    
    return df


def main(limit: int = None):
    """
    主函数：查询 CWE 表的数据

    Args:
        limit: 限制返回的记录数，None 表示返回所有记录
    """
    logger.info("=" * 60)
    logger.info("查询 CWE 表数据")
    logger.info("=" * 60)

    # 初始化数据库连接
    db_connector = DatabaseConnector()

    # 执行查询
    result_df = query_cwe_table(db_connector, limit=limit)

    # 打印统计信息
    logger.info("\n" + "=" * 60)
    logger.info("统计信息:")
    logger.info(f"  总记录数: {len(result_df)}")
    logger.info(f"  唯一 CWE ID 数: {result_df['cwe_id'].nunique()}")
    logger.info(f"  类别数量 (is_category=True): {result_df['is_category'].sum() if 'is_category' in result_df.columns else 'N/A'}")
    logger.info("=" * 60)

    # 显示前几条记录
    logger.info("\n前10条记录:")
    print("\n" + result_df.head(10).to_string())
    
    # 显示一些常见的 CWE
    logger.info("\n一些常见的 CWE:")
    common_cwe_ids = ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-22', 'CWE-78', 'CWE-352', 'CWE-434', 'CWE-94', 'CWE-502']
    common_cwe = result_df[result_df['cwe_id'].isin(common_cwe_ids)]
    if len(common_cwe) > 0:
        print("\n" + common_cwe[['cwe_id', 'cwe_name', 'is_category']].to_string(index=False))
    
    logger.info("\n查询完成！")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="查询 CWE 表的数据")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="限制返回的记录数（默认: 返回所有记录）",
    )
    
    args = parser.parse_args()
    main(limit=args.limit)

