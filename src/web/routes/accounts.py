"""
账号管理 API 路由
"""
import io
import json
import logging
import zipfile
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, Body
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ...config.constants import AccountStatus
from ...config.settings import get_settings
from ...core.openai.token_refresh import refresh_account_token as do_refresh
from ...core.openai.token_refresh import validate_account_token as do_validate
from ...core.upload.cpa_upload import generate_token_json, batch_upload_to_cpa, upload_to_cpa
from ...core.upload.team_manager_upload import upload_to_team_manager, batch_upload_to_team_manager
from ...core.upload.sub2api_upload import batch_upload_to_sub2api, upload_to_sub2api

from ...database import crud
from ...database.models import Account
from ...database.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


# ============================================================
# 辅助：根据 validate_token 返回的错误字符串推断账号状态
# ============================================================
def _status_from_validate_error(error: Optional[str]) -> Optional[str]:
    """
    返回 None 表示不修改状态（网络波动，不确定）。
    """
    if error is None:
        return None
    e = error.lower()
    if "banned" in e:
        return "banned"
    if "network" in e or "timeout" in e or "connection" in e:
        return None        # 临时故障，不改状态
    # token_expired、invalid 等 → expired
    return "expired"


# ============== Pydantic Models ==============

class AccountResponse(BaseModel):
    id: int
    email: str
    password: Optional[str] = None
    client_id: Optional[str] = None
    email_service: str
    account_id: Optional[str] = None
    workspace_id: Optional[str] = None
    registered_at: Optional[str] = None
    last_refresh: Optional[str] = None
    expires_at: Optional[str] = None
    status: str
    proxy_used: Optional[str] = None
    cpa_uploaded: bool = False
    cpa_uploaded_at: Optional[str] = None
    cookies: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


class AccountListResponse(BaseModel):
    total: int
    accounts: List[AccountResponse]


class AccountUpdateRequest(BaseModel):
    status: Optional[str] = None
    metadata: Optional[dict] = None
    cookies: Optional[str] = None


class BatchDeleteRequest(BaseModel):
    ids: List[int] = []
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None


class BatchUpdateRequest(BaseModel):
    ids: List[int]
    status: str


# ============== Helper Functions ==============

def resolve_account_ids(
    db,
    ids: List[int],
    select_all: bool = False,
    status_filter: Optional[str] = None,
    email_service_filter: Optional[str] = None,
    search_filter: Optional[str] = None,
) -> List[int]:
    if not select_all:
        return ids
    query = db.query(Account.id)
    if status_filter:
        query = query.filter(Account.status == status_filter)
    if email_service_filter:
        query = query.filter(Account.email_service == email_service_filter)
    if search_filter:
        pattern = f"%{search_filter}%"
        query = query.filter(
            (Account.email.ilike(pattern)) | (Account.account_id.ilike(pattern))
        )
    return [row[0] for row in query.all()]


def account_to_response(account: Account) -> AccountResponse:
    return AccountResponse(
        id=account.id,
        email=account.email,
        password=account.password,
        client_id=account.client_id,
        email_service=account.email_service,
        account_id=account.account_id,
        workspace_id=account.workspace_id,
        registered_at=account.registered_at.isoformat() if account.registered_at else None,
        last_refresh=account.last_refresh.isoformat() if account.last_refresh else None,
        expires_at=account.expires_at.isoformat() if account.expires_at else None,
        status=account.status,
        proxy_used=account.proxy_used,
        cpa_uploaded=account.cpa_uploaded or False,
        cpa_uploaded_at=account.cpa_uploaded_at.isoformat() if account.cpa_uploaded_at else None,
        cookies=account.cookies,
        created_at=account.created_at.isoformat() if account.created_at else None,
        updated_at=account.updated_at.isoformat() if account.updated_at else None,
    )


# ============== API Endpoints ==============

@router.get("", response_model=AccountListResponse)
async def list_accounts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    email_service: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    with get_db() as db:
        query = db.query(Account)
        if status:
            query = query.filter(Account.status == status)
        if email_service:
            query = query.filter(Account.email_service == email_service)
        if search:
            p = f"%{search}%"
            query = query.filter(
                (Account.email.ilike(p)) | (Account.account_id.ilike(p))
            )
        total    = query.count()
        offset   = (page - 1) * page_size
        accounts = query.order_by(Account.created_at.desc()).offset(offset).limit(page_size).all()
        return AccountListResponse(total=total, accounts=[account_to_response(a) for a in accounts])


@router.get("/{account_id}", response_model=AccountResponse)
async def get_account(account_id: int):
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        return account_to_response(account)


@router.get("/{account_id}/tokens")
async def get_account_tokens(account_id: int):
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        return {
            "id": account.id,
            "email": account.email,
            "access_token": account.access_token,
            "refresh_token": account.refresh_token,
            "id_token": account.id_token,
            "has_tokens": bool(account.access_token and account.refresh_token),
        }


@router.patch("/{account_id}", response_model=AccountResponse)
async def update_account(account_id: int, request: AccountUpdateRequest):
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        update_data = {}
        if request.status:
            if request.status not in [e.value for e in AccountStatus]:
                raise HTTPException(status_code=400, detail="无效的状态值")
            update_data["status"] = request.status
        if request.metadata:
            current_metadata = account.metadata or {}
            current_metadata.update(request.metadata)
            update_data["metadata"] = current_metadata
        if request.cookies is not None:
            update_data["cookies"] = request.cookies or None
        account = crud.update_account(db, account_id, **update_data)
        return account_to_response(account)


@router.get("/{account_id}/cookies")
async def get_account_cookies(account_id: int):
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        return {"account_id": account_id, "cookies": account.cookies or ""}


@router.delete("/{account_id}")
async def delete_account(account_id: int):
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        crud.delete_account(db, account_id)
        return {"success": True, "message": f"账号 {account.email} 已删除"}


@router.post("/batch-delete")
async def batch_delete_accounts(request: BatchDeleteRequest):
    with get_db() as db:
        ids = resolve_account_ids(
            db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter
        )
        deleted_count = 0
        errors = []
        for account_id in ids:
            try:
                if crud.get_account_by_id(db, account_id):
                    crud.delete_account(db, account_id)
                    deleted_count += 1
            except Exception as e:
                errors.append(f"ID {account_id}: {str(e)}")
        return {"success": True, "deleted_count": deleted_count, "errors": errors or None}


@router.post("/batch-update")
async def batch_update_accounts(request: BatchUpdateRequest):
    if request.status not in [e.value for e in AccountStatus]:
        raise HTTPException(status_code=400, detail="无效的状态值")
    with get_db() as db:
        updated_count = 0
        errors = []
        for account_id in request.ids:
            try:
                if crud.get_account_by_id(db, account_id):
                    crud.update_account(db, account_id, status=request.status)
                    updated_count += 1
            except Exception as e:
                errors.append(f"ID {account_id}: {str(e)}")
        return {"success": True, "updated_count": updated_count, "errors": errors or None}


class BatchExportRequest(BaseModel):
    ids: List[int] = []
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None


@router.post("/export/json")
async def export_accounts_json(request: BatchExportRequest):
    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)
        accounts = db.query(Account).filter(Account.id.in_(ids)).all()
        export_data = [{
            "email": a.email, "password": a.password, "client_id": a.client_id,
            "account_id": a.account_id, "workspace_id": a.workspace_id,
            "access_token": a.access_token, "refresh_token": a.refresh_token,
            "id_token": a.id_token, "session_token": a.session_token,
            "email_service": a.email_service,
            "registered_at": a.registered_at.isoformat() if a.registered_at else None,
            "last_refresh": a.last_refresh.isoformat() if a.last_refresh else None,
            "expires_at": a.expires_at.isoformat() if a.expires_at else None,
            "status": a.status,
        } for a in accounts]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return StreamingResponse(
            iter([json.dumps(export_data, ensure_ascii=False, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=accounts_{timestamp}.json"}
        )


@router.post("/export/csv")
async def export_accounts_csv(request: BatchExportRequest):
    import csv
    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)
        accounts = db.query(Account).filter(Account.id.in_(ids)).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID","Email","Password","Client ID","Account ID","Workspace ID",
            "Access Token","Refresh Token","ID Token","Session Token",
            "Email Service","Status","Registered At","Last Refresh","Expires At"])
        for a in accounts:
            writer.writerow([a.id, a.email, a.password or "", a.client_id or "",
                a.account_id or "", a.workspace_id or "",
                a.access_token or "", a.refresh_token or "",
                a.id_token or "", a.session_token or "",
                a.email_service, a.status,
                a.registered_at.isoformat() if a.registered_at else "",
                a.last_refresh.isoformat() if a.last_refresh else "",
                a.expires_at.isoformat() if a.expires_at else ""])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=accounts_{timestamp}.csv"})


@router.post("/export/sub2api")
async def export_accounts_sub2api(request: BatchExportRequest):
    def make_entry(acc):
        return {
            "name": acc.email, "platform": "openai", "type": "oauth",
            "credentials": {
                "access_token": acc.access_token or "",
                "chatgpt_account_id": acc.account_id or "",
                "chatgpt_user_id": "", "client_id": acc.client_id or "",
                "expires_at": int(acc.expires_at.timestamp()) if acc.expires_at else 0,
                "expires_in": 863999,
                "model_mapping": {
                    "gpt-5.1":"gpt-5.1","gpt-5.1-codex":"gpt-5.1-codex",
                    "gpt-5.1-codex-max":"gpt-5.1-codex-max","gpt-5.1-codex-mini":"gpt-5.1-codex-mini",
                    "gpt-5.2":"gpt-5.2","gpt-5.2-codex":"gpt-5.2-codex",
                    "gpt-5.3":"gpt-5.3","gpt-5.3-codex":"gpt-5.3-codex","gpt-5.4":"gpt-5.4"
                },
                "organization_id": acc.workspace_id or "",
                "refresh_token": acc.refresh_token or "",
            },
            "extra": {}, "concurrency": 10, "priority": 1,
            "rate_multiplier": 1, "auto_pause_on_expired": True
        }
    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)
        accounts = db.query(Account).filter(Account.id.in_(ids)).all()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        payload   = {"proxies": [], "accounts": [make_entry(a) for a in accounts]}
        filename  = f"{accounts[0].email}_sub2api.json" if len(accounts) == 1 else f"sub2api_tokens_{timestamp}.json"
        return StreamingResponse(
            iter([json.dumps(payload, ensure_ascii=False, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"})


@router.post("/export/cpa")
async def export_accounts_cpa(request: BatchExportRequest):
    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)
        accounts = db.query(Account).filter(Account.id.in_(ids)).all()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if len(accounts) == 1:
            acc      = accounts[0]
            content  = json.dumps(generate_token_json(acc), ensure_ascii=False, indent=2)
            return StreamingResponse(iter([content]), media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename={acc.email}.json"})
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for acc in accounts:
                zf.writestr(f"{acc.email}.json",
                    json.dumps(generate_token_json(acc), ensure_ascii=False, indent=2))
        buf.seek(0)
        return StreamingResponse(buf, media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=cpa_tokens_{timestamp}.zip"})


@router.get("/stats/summary")
async def get_accounts_stats():
    with get_db() as db:
        from sqlalchemy import func
        total        = db.query(func.count(Account.id)).scalar()
        status_stats = db.query(Account.status, func.count(Account.id)).group_by(Account.status).all()
        svc_stats    = db.query(Account.email_service, func.count(Account.id)).group_by(Account.email_service).all()
        return {
            "total": total,
            "by_status":        {s: c for s, c in status_stats},
            "by_email_service": {s: c for s, c in svc_stats},
        }


# ============== Token 刷新 ==============

class TokenRefreshRequest(BaseModel):
    proxy: Optional[str] = None

class BatchRefreshRequest(BaseModel):
    ids: List[int] = []
    proxy: Optional[str] = None
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None

class TokenValidateRequest(BaseModel):
    proxy: Optional[str] = None

class BatchValidateRequest(BaseModel):
    ids: List[int] = []
    proxy: Optional[str] = None
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None


@router.post("/batch-refresh")
async def batch_refresh_tokens(request: BatchRefreshRequest, background_tasks: BackgroundTasks):
    """
    批量刷新 Token，并按错误类型精确回写账号状态：
      成功                → active
      refresh_token_reused → failed  （token 链断裂，不可恢复）
      banned / abuse       → banned
      token 过期 / 其他    → expired  （可尝试重新授权）
      网络错误             → 不改状态  （临时故障）
    """
    proxy = request.proxy or get_settings().proxy_url

    results = {"success_count": 0, "failed_count": 0, "errors": []}

    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)

    for account_id in ids:
        try:
            result      = do_refresh(account_id, proxy)
            new_status  = result.suggested_status()
            if result.success:
                results["success_count"] += 1
            else:
                results["failed_count"] += 1
                results["errors"].append({"id": account_id, "error": result.error_message,
                                          "error_type": result.error_type})
            if new_status is not None:
                with get_db() as db:
                    crud.update_account(db, account_id, status=new_status)
                logger.info(f"账号 {account_id} 状态已更新 → {new_status}（{result.error_type}）")
        except Exception as e:
            results["failed_count"] += 1
            results["errors"].append({"id": account_id, "error": str(e)})

    return results


@router.post("/{account_id}/refresh")
async def refresh_account_token(account_id: int, request: Optional[TokenRefreshRequest] = Body(default=None)):
    proxy       = request.proxy if request and request.proxy else get_settings().proxy_url
    result      = do_refresh(account_id, proxy)
    new_status  = result.suggested_status()
    if new_status is not None:
        with get_db() as db:
            crud.update_account(db, account_id, status=new_status)

    if result.success:
        return {"success": True, "message": "Token 刷新成功",
                "expires_at": result.expires_at.isoformat() if result.expires_at else None}
    return {"success": False, "error": result.error_message, "error_type": result.error_type}


@router.post("/batch-validate")
async def batch_validate_tokens(request: BatchValidateRequest):
    """
    批量验证 Token，并精确回写账号状态：
      有效              → active
      banned            → banned
      无效 / 过期       → expired
      网络错误          → 不改状态
    """
    proxy = request.proxy or get_settings().proxy_url

    results = {"valid_count": 0, "invalid_count": 0, "details": []}

    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)

    for account_id in ids:
        try:
            is_valid, error = do_validate(account_id, proxy)
            results["details"].append({"id": account_id, "valid": is_valid, "error": error})

            if is_valid:
                results["valid_count"] += 1
                with get_db() as db:
                    crud.update_account(db, account_id, status="active")
            else:
                results["invalid_count"] += 1
                new_status = _status_from_validate_error(error)
                if new_status is not None:
                    with get_db() as db:
                        crud.update_account(db, account_id, status=new_status)
                    logger.info(f"账号 {account_id} 验证失败，状态 → {new_status}（{error}）")
                else:
                    logger.info(f"账号 {account_id} 验证失败（网络波动），状态不变（{error}）")
        except Exception as e:
            results["invalid_count"] += 1
            results["details"].append({"id": account_id, "valid": False, "error": str(e)})

    return results


@router.post("/{account_id}/validate")
async def validate_account_token(account_id: int, request: Optional[TokenValidateRequest] = Body(default=None)):
    proxy    = request.proxy if request and request.proxy else get_settings().proxy_url
    is_valid, error = do_validate(account_id, proxy)

    if is_valid:
        with get_db() as db:
            crud.update_account(db, account_id, status="active")
    else:
        new_status = _status_from_validate_error(error)
        if new_status is not None:
            with get_db() as db:
                crud.update_account(db, account_id, status=new_status)

    return {"id": account_id, "valid": is_valid, "error": error}


# ============== CPA 上传 ==============

class CPAUploadRequest(BaseModel):
    proxy: Optional[str] = None
    cpa_service_id: Optional[int] = None

class BatchCPAUploadRequest(BaseModel):
    ids: List[int] = []
    proxy: Optional[str] = None
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None
    cpa_service_id: Optional[int] = None


@router.post("/batch-upload-cpa")
async def batch_upload_accounts_to_cpa(request: BatchCPAUploadRequest):
    proxy = request.proxy or get_settings().proxy_url
    cpa_api_url = cpa_api_token = None
    if request.cpa_service_id:
        with get_db() as db:
            svc = crud.get_cpa_service_by_id(db, request.cpa_service_id)
            if not svc:
                raise HTTPException(status_code=404, detail="指定的 CPA 服务不存在")
            cpa_api_url, cpa_api_token = svc.api_url, svc.api_token
    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)
    return batch_upload_to_cpa(ids, proxy, api_url=cpa_api_url, api_token=cpa_api_token)


@router.post("/{account_id}/upload-cpa")
async def upload_account_to_cpa(account_id: int, request: Optional[CPAUploadRequest] = Body(default=None)):
    proxy          = request.proxy if request and request.proxy else get_settings().proxy_url
    cpa_service_id = request.cpa_service_id if request else None
    cpa_api_url = cpa_api_token = None
    if cpa_service_id:
        with get_db() as db:
            svc = crud.get_cpa_service_by_id(db, cpa_service_id)
            if not svc:
                raise HTTPException(status_code=404, detail="指定的 CPA 服务不存在")
            cpa_api_url, cpa_api_token = svc.api_url, svc.api_token
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        if not account.access_token:
            return {"success": False, "error": "账号缺少 Token，无法上传"}
        success, message = upload_to_cpa(generate_token_json(account), proxy,
                                         api_url=cpa_api_url, api_token=cpa_api_token)
        if success:
            account.cpa_uploaded    = True
            account.cpa_uploaded_at = datetime.utcnow()
            db.commit()
        return {"success": success, "message" if success else "error": message}


# ============== Sub2API 上传 ==============

class Sub2ApiUploadRequest(BaseModel):
    service_id: Optional[int] = None
    concurrency: int = 3
    priority: int = 50

class BatchSub2ApiUploadRequest(BaseModel):
    ids: List[int] = []
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None
    service_id: Optional[int] = None
    concurrency: int = 3
    priority: int = 50


def _resolve_sub2api_service(service_id):
    api_url = api_key = None
    with get_db() as db:
        if service_id:
            svc = crud.get_sub2api_service_by_id(db, service_id)
            if not svc:
                raise HTTPException(status_code=404, detail="指定的 Sub2API 服务不存在")
        else:
            svcs = crud.get_sub2api_services(db, enabled=True)
            svc  = svcs[0] if svcs else None
        if svc:
            api_url, api_key = svc.api_url, svc.api_key
    if not api_url or not api_key:
        raise HTTPException(status_code=400, detail="未找到可用的 Sub2API 服务，请先在设置中配置")
    return api_url, api_key


@router.post("/batch-upload-sub2api")
async def batch_upload_accounts_to_sub2api(request: BatchSub2ApiUploadRequest):
    api_url, api_key = _resolve_sub2api_service(request.service_id)
    with get_db() as db:
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)
    return batch_upload_to_sub2api(ids, api_url, api_key,
                                   concurrency=request.concurrency, priority=request.priority)


@router.post("/{account_id}/upload-sub2api")
async def upload_account_to_sub2api(account_id: int, request: Optional[Sub2ApiUploadRequest] = Body(default=None)):
    api_url, api_key = _resolve_sub2api_service(request.service_id if request else None)
    concurrency = request.concurrency if request else 3
    priority    = request.priority    if request else 50
    with get_db() as db:
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        if not account.access_token:
            return {"success": False, "error": "账号缺少 Token，无法上传"}
        success, message = upload_to_sub2api([account], api_url, api_key,
                                             concurrency=concurrency, priority=priority)
    return {"success": success, "message" if success else "error": message}


# ============== Team Manager 上传 ==============

class UploadTMRequest(BaseModel):
    service_id: Optional[int] = None

class BatchUploadTMRequest(BaseModel):
    ids: List[int] = []
    select_all: bool = False
    status_filter: Optional[str] = None
    email_service_filter: Optional[str] = None
    search_filter: Optional[str] = None
    service_id: Optional[int] = None


def _resolve_tm_service(db, service_id):
    if service_id:
        svc = crud.get_tm_service_by_id(db, service_id)
    else:
        svcs = crud.get_tm_services(db, enabled=True)
        svc  = svcs[0] if svcs else None
    if not svc:
        raise HTTPException(status_code=400, detail="未找到可用的 Team Manager 服务，请先在设置中配置")
    return svc.api_url, svc.api_key


@router.post("/batch-upload-tm")
async def batch_upload_accounts_to_tm(request: BatchUploadTMRequest):
    with get_db() as db:
        api_url, api_key = _resolve_tm_service(db, request.service_id)
        ids = resolve_account_ids(db, request.ids, request.select_all,
            request.status_filter, request.email_service_filter, request.search_filter)
    return batch_upload_to_team_manager(ids, api_url, api_key)


@router.post("/{account_id}/upload-tm")
async def upload_account_to_tm(account_id: int, request: Optional[UploadTMRequest] = Body(default=None)):
    with get_db() as db:
        api_url, api_key = _resolve_tm_service(db, request.service_id if request else None)
        account = crud.get_account_by_id(db, account_id)
        if not account:
            raise HTTPException(status_code=404, detail="账号不存在")
        success, message = upload_to_team_manager(account, api_url, api_key)
    return {"success": success, "message": message}
