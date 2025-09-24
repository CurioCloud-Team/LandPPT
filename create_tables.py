#!/usr/bin/env python3
"""
手动创建数据库表
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from landppt.database.database import init_db

if __name__ == "__main__":
    print("正在创建数据库表...")
    import asyncio
    asyncio.run(init_db())
    print("数据库表创建完成")