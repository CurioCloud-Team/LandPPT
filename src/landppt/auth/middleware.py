"""
Authentication middleware for LandPPT
"""

from typing import Optional, Callable
from fastapi import Request, Response, HTTPException, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import logging

from .auth_service import get_auth_service, AuthService
from ..database.database import get_db
from ..database.models import User

logger = logging.getLogger(__name__)


class AuthMiddleware:
    """Authentication middleware"""
    
    def __init__(self):
        self.auth_service = get_auth_service()
        # 不需要认证的路径
        self.public_paths = {
            "/",
            "/auth/login",
            "/auth/logout",
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/jwt/login",  # JWT登录端点
            "/api/auth/check",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/static",
            "/favicon.ico",
            "/health"  # 健康检查端点公开访问
        }
        # 不需要认证的路径前缀
        self.public_prefixes = [
            "/static/",
            "/temp/",  # 添加temp目录用于图片缓存访问
            "/api/image/view/",  # 图床图片访问无需认证
            "/api/image/thumbnail/",  # 图片缩略图访问无需认证
            "/docs",
            "/redoc",
            "/openapi.json"
        ]
    
    def is_public_path(self, path: str) -> bool:
        """Check if path is public (doesn't require authentication)"""
        # Check exact matches
        if path in self.public_paths:
            return True
        
        # Check prefixes
        for prefix in self.public_prefixes:
            if path.startswith(prefix):
                return True
        
        return False
    
    async def __call__(self, request: Request, call_next: Callable):
        """Middleware function"""
        path = request.url.path
        
        # Skip authentication for public paths
        if self.is_public_path(path):
            response = await call_next(request)
            return response
        
        # Get database session for authentication checks
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            user = None
            
            # First, try to authenticate via Bearer token (for API calls)
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                
                # Check for hardcoded integration API key
                if token == "curio_cloud_integration_key_2024":
                    # Create a dummy user for API integration
                    from ..database.models import User
                    dummy_user = User(
                        id=999999,
                        username="curio_cloud_api",
                        email="api@curio.cloud",
                        is_active=True
                    )
                    user = dummy_user
                else:
                    # Try JWT token first
                    payload = self.auth_service.verify_token(token)
                    if payload:
                        user_id = payload.get("user_id")
                        if user_id:
                            user = self.auth_service.get_user_by_id(db, user_id)
                    # If JWT failed, try API key from database
                    if not user:
                        user = self.auth_service.get_user_by_api_key(db, token)
            
            # If no Bearer token auth succeeded, try session-based auth
            if not user:
                session_id = request.cookies.get("session_id")
                if session_id:
                    user = self.auth_service.get_user_by_session(db, session_id)
            
            # If still no user authenticated
            if not user:
                # No authentication, redirect to login
                if path.startswith("/api/"):
                    # API endpoints return 401
                    return Response(
                        content='{"detail": "Authentication required"}',
                        status_code=401,
                        media_type="application/json"
                    )
                else:
                    # Web endpoints redirect to login
                    return RedirectResponse(url="/auth/login", status_code=302)
            
            # Add user to request state
            request.state.user = user
            
            # Continue with request
            response = await call_next(request)
            return response
            
        except Exception as e:
            logger.error(f"Authentication middleware error: {e}")
            if path.startswith("/api/"):
                return Response(
                    content='{"detail": "Authentication error"}',
                    status_code=500,
                    media_type="application/json"
                )
            else:
                return RedirectResponse(url="/auth/login", status_code=302)
        finally:
            db.close()


def get_current_user(request: Request) -> Optional[User]:
    """Get current authenticated user from request"""
    return getattr(request.state, 'user', None)


def require_auth(request: Request) -> User:
    """Dependency to require authentication"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(request: Request) -> User:
    """Dependency to require admin privileges"""
    user = require_auth(request)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None

    auth_service = get_auth_service()
    return auth_service.get_user_by_session(db, session_id)


def get_current_user_required(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    """Get current user, raise exception if not authenticated"""
    user = get_current_user_optional(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def get_current_admin_user(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    """Get current admin user, raise exception if not admin"""
    user = get_current_user_required(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def create_auth_middleware() -> AuthMiddleware:
    """Create authentication middleware instance"""
    return AuthMiddleware()


# Utility functions for templates
def is_authenticated(request: Request) -> bool:
    """Check if user is authenticated"""
    return get_current_user(request) is not None


def is_admin(request: Request) -> bool:
    """Check if user is admin"""
    user = get_current_user(request)
    return user is not None and user.is_admin


def get_user_info(request: Request) -> Optional[dict]:
    """Get user info for templates"""
    user = get_current_user(request)
    if user:
        return user.to_dict()
    return None
