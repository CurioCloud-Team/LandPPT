#!/usr/bin/env python3
"""
获取或创建LandPPT API密钥的脚本
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from landppt.database.database import SessionLocal
from landppt.auth.auth_service import get_auth_service
from landppt.database.models import User, ApiKey

def main():
    db = SessionLocal()
    try:
        auth_service = get_auth_service()

        # 查找或创建管理员用户
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            print("创建管理员用户...")
            admin_user = auth_service.create_user(
                db=db,
                username="admin",
                password="admin123",
                is_admin=True
            )
            print(f"管理员用户已创建: {admin_user.username}")

        # 检查是否已有API密钥
        existing_keys = db.query(ApiKey).filter(
            ApiKey.user_id == admin_user.id,
            ApiKey.is_active == True
        ).all()

        if existing_keys:
            print("现有的API密钥：")
            for key in existing_keys:
                print(f"  名称: {key.name}")
                print(f"  密钥: {key.api_key}")
                print(f"  创建时间: {key.created_at}")
                print()
        else:
            print("没有找到活跃的API密钥，正在创建新的...")
            # 创建新的API密钥
            api_key_obj = auth_service.create_api_key(db, admin_user, "CurioCloud Integration Key")
            print("新创建的API密钥：")
            print(f"  名称: {api_key_obj.name}")
            print(f"  密钥: {api_key_obj.api_key}")
            print(f"  创建时间: {api_key_obj.created_at}")
            print()
            print("请在CurioCloud的.env文件中设置:")
            print(f"LANDPPT_API_KEY={api_key_obj.api_key}")

    finally:
        db.close()

if __name__ == "__main__":
    main()