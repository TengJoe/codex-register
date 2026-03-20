"""
Token 刷新模块
支持 Session Token 和 OAuth Refresh Token 两种刷新方式
"""

import logging
import json
import time
import threading
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from curl_cffi import requests as cffi_requests

from ...config.settings import get_settings
from ...database.session import get_db
from ...database import crud
from ...database.models import Account

logger = logging.getLogger(__name__)

# ============================================================
# 错误类型枚举，用于调用方根据原因决定写入哪个账号状态
# ============================================================
class RefreshErrorType:
    NONE            = "none"             # 无错误
    TOKEN_REUSED    = "token_reused"     # refresh_token 已被用过 → failed
    BANNED          = "banned"           # 账号封禁 / service_abuse → banned
    EXPIRED         = "expired"          # token 普通过期 / invalid_grant → expired
    NETWORK         = "network"          # 网络/超时 → 不改状态
    UNKNOWN         = "unknown"          # 未知 → expired 保守处理


# ============================================================
# 账号级别互斥锁，防止并发刷新触发 Rotation 冲突
# ============================================================
_refresh_locks: Dict[int, threading.Lock] = {}
_refresh_locks_meta = threading.Lock()


def _get_account_lock(account_id: int) -> threading.Lock:
    if account_id not in _refresh_locks:
        with _refresh_locks_meta:
            if account_id not in _refresh_locks:
                _refresh_locks[account_id] = threading.Lock()
    return _refresh_locks[account_id]


def _classify_oauth_error(status_code: int, body: str) -> str:
    """
    根据 HTTP 状态码和响应体，将刷新失败分类为具体错误类型。
    """
    body_lower = body.lower()

    if status_code == 401:
        if "refresh_token_reused" in body_lower or "already been used" in body_lower:
            return RefreshErrorType.TOKEN_REUSED
        if "service_abuse" in body_lower or "abuse" in body_lower:
            return RefreshErrorType.BANNED
        if "invalid_grant" in body_lower or "expired" in body_lower:
            return RefreshErrorType.EXPIRED
        # 其他 401，保守处理为 expired
        return RefreshErrorType.EXPIRED

    if status_code == 403:
        return RefreshErrorType.BANNED

    if status_code >= 500 or status_code == 0:
        return RefreshErrorType.NETWORK

    return RefreshErrorType.UNKNOWN


@dataclass
class TokenRefreshResult:
    """Token 刷新结果"""
    success: bool
    access_token: str = ""
    refresh_token: str = ""
    expires_at: Optional[datetime] = None
    error_message: str = ""
    error_type: str = RefreshErrorType.NONE   # 新增：失败原因分类

    def suggested_status(self) -> Optional[str]:
        """
        根据错误类型给出建议的账号状态。
        返回 None 表示不修改状态（如网络错误）。
        """
        if self.success:
            return "active"
        mapping = {
            RefreshErrorType.TOKEN_REUSED: "failed",
            RefreshErrorType.BANNED:       "banned",
            RefreshErrorType.EXPIRED:      "expired",
            RefreshErrorType.UNKNOWN:      "expired",
            RefreshErrorType.NETWORK:      None,   # 不改，可能是临时故障
        }
        return mapping.get(self.error_type, "expired")


class TokenRefreshManager:
    SESSION_URL = "https://chatgpt.com/api/auth/session"
    TOKEN_URL   = "https://auth.openai.com/oauth/token"

    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url
        self.settings  = get_settings()

    def _create_session(self) -> cffi_requests.Session:
        return cffi_requests.Session(impersonate="chrome120", proxy=self.proxy_url)

    def refresh_by_session_token(self, session_token: str) -> TokenRefreshResult:
        result = TokenRefreshResult(success=False)
        try:
            session = self._create_session()
            session.cookies.set(
                "__Secure-next-auth.session-token",
                session_token,
                domain=".chatgpt.com",
                path="/"
            )
            response = session.get(
                self.SESSION_URL,
                headers={
                    "accept": "application/json",
                    "user-agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    )
                },
                timeout=30
            )
            if response.status_code != 200:
                result.error_type    = _classify_oauth_error(response.status_code, response.text)
                result.error_message = f"Session token 刷新失败: HTTP {response.status_code}"
                logger.warning(result.error_message)
                return result

            data         = response.json()
            access_token = data.get("accessToken")
            if not access_token:
                result.error_type    = RefreshErrorType.EXPIRED
                result.error_message = "Session token 刷新失败: 未找到 accessToken"
                logger.warning(result.error_message)
                return result

            expires_at  = None
            expires_str = data.get("expires")
            if expires_str:
                try:
                    expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
                except Exception:
                    pass

            result.success      = True
            result.access_token = access_token
            result.expires_at   = expires_at
            logger.info(f"Session token 刷新成功，过期时间: {expires_at}")
            return result

        except Exception as e:
            result.error_type    = RefreshErrorType.NETWORK
            result.error_message = f"Session token 刷新异常: {str(e)}"
            logger.error(result.error_message)
            return result

    def refresh_by_oauth_token(
        self,
        refresh_token: str,
        client_id: Optional[str] = None
    ) -> TokenRefreshResult:
        result = TokenRefreshResult(success=False)
        try:
            session   = self._create_session()
            client_id = client_id or self.settings.openai_client_id

            response = session.post(
                self.TOKEN_URL,
                headers={
                    "content-type": "application/x-www-form-urlencoded",
                    "accept":        "application/json"
                },
                data={
                    "client_id":    client_id,
                    "grant_type":   "refresh_token",
                    "refresh_token": refresh_token,
                    "redirect_uri": self.settings.openai_redirect_uri
                },
                timeout=30
            )

            if response.status_code != 200:
                error_body           = response.text[:500]
                result.error_type    = _classify_oauth_error(response.status_code, error_body)
                result.error_message = (
                    f"OAuth token 刷新失败: HTTP {response.status_code}, "
                    f"响应: {error_body}"
                )
                logger.warning(result.error_message)
                return result

            data         = response.json()
            access_token = data.get("access_token")
            if not access_token:
                result.error_type    = RefreshErrorType.EXPIRED
                result.error_message = "OAuth token 刷新失败: 未找到 access_token"
                logger.warning(result.error_message)
                return result

            new_refresh_token = data.get("refresh_token") or ""
            expires_in        = data.get("expires_in", 3600)
            expires_at        = datetime.utcnow() + timedelta(seconds=expires_in)

            result.success       = True
            result.access_token  = access_token
            result.refresh_token = new_refresh_token if new_refresh_token else refresh_token
            result.expires_at    = expires_at

            if new_refresh_token and new_refresh_token != refresh_token:
                logger.info("OAuth token 刷新成功（Rotation：已获取新 refresh_token）")
            else:
                logger.info(f"OAuth token 刷新成功，过期时间: {expires_at}")
            return result

        except Exception as e:
            result.error_type    = RefreshErrorType.NETWORK
            result.error_message = f"OAuth token 刷新异常: {str(e)}"
            logger.error(result.error_message)
            return result

    def refresh_account(self, account: Account) -> TokenRefreshResult:
        if account.session_token:
            logger.info(f"尝试使用 Session Token 刷新账号 {account.email}")
            result = self.refresh_by_session_token(account.session_token)
            if result.success:
                return result
            # Session Token 刷新失败时，若是网络问题就直接返回，避免用旧 refresh_token 再试
            if result.error_type == RefreshErrorType.NETWORK:
                return result
            logger.warning("Session Token 刷新失败，尝试 OAuth 刷新")

        if account.refresh_token:
            logger.info(f"尝试使用 OAuth Refresh Token 刷新账号 {account.email}")
            return self.refresh_by_oauth_token(
                refresh_token=account.refresh_token,
                client_id=account.client_id
            )

        return TokenRefreshResult(
            success=False,
            error_type=RefreshErrorType.EXPIRED,
            error_message="账号没有可用的刷新方式（缺少 session_token 和 refresh_token）"
        )

    def validate_token(self, access_token: str) -> Tuple[bool, Optional[str]]:
        try:
            session  = self._create_session()
            response = session.get(
                "https://chatgpt.com/backend-api/me",
                headers={
                    "authorization": f"Bearer {access_token}",
                    "accept":        "application/json"
                },
                timeout=30
            )
            if response.status_code == 200:
                return True, None
            if response.status_code == 401:
                return False, "token_expired"
            if response.status_code == 403:
                return False, "banned"
            return False, f"HTTP {response.status_code}"
        except Exception as e:
            return False, f"network:{str(e)}"


def refresh_account_token(account_id: int, proxy_url: Optional[str] = None) -> TokenRefreshResult:
    """
    刷新指定账号的 Token 并更新数据库。
    使用账号级互斥锁防止并发 Rotation 冲突。
    """
    lock     = _get_account_lock(account_id)
    acquired = lock.acquire(timeout=60)
    if not acquired:
        logger.warning(f"账号 {account_id} 刷新锁等待超时")
        return TokenRefreshResult(
            success=False,
            error_type=RefreshErrorType.NETWORK,
            error_message="刷新锁等待超时"
        )

    try:
        with get_db() as db:
            account = crud.get_account_by_id(db, account_id)
            if not account:
                return TokenRefreshResult(
                    success=False,
                    error_type=RefreshErrorType.UNKNOWN,
                    error_message="账号不存在"
                )

            manager = TokenRefreshManager(proxy_url=proxy_url)
            result  = manager.refresh_account(account)

            if result.success:
                update_data = {
                    "access_token": result.access_token,
                    "last_refresh": datetime.utcnow()
                }
                # Rotation：新 refresh_token 必须立即持久化
                if result.refresh_token and result.refresh_token != account.refresh_token:
                    update_data["refresh_token"] = result.refresh_token
                    logger.info(f"账号 {account_id} refresh_token 已更新（Rotation）")
                if result.expires_at:
                    update_data["expires_at"] = result.expires_at
                crud.update_account(db, account_id, **update_data)

            return result
    finally:
        lock.release()


def validate_account_token(account_id: int, proxy_url: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            return False, "账号不存在"
        if not account.access_token:
            return False, "账号没有 access_token"
        manager = TokenRefreshManager(proxy_url=proxy_url)
        return manager.validate_token(account.access_token)
