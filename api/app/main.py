"""显微成像原片单实例 API。

安全边界：
  * 明文原片只在请求/响应的内存流中存在，密文 blob 直接落盘；
  * 明文 DEK 只在单次请求内存中存活，元数据库只存信封密文；
  * 主密钥材料永远只在密钥服务内，本服务通过内部 HTTP 调用包裹/解包。
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

BLOB_DIR = os.environ.get("BLOB_DIR", "/data/blobs")
DB_PATH = os.environ.get("METADATA_DB", "/data/metadata.db")
KEY_SERVICE_URL = os.environ.get("KEY_SERVICE_URL", "http://keystore:8001")
KEY_SERVICE_TOKEN = os.environ.get("KEY_SERVICE_TOKEN", "dev-only-key-service-token")
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 ** 3)))

# 安全约束：Starlette 的 multipart 解析器默认把 >1MiB 的表单文件假脱机到
# 磁盘临时文件，等于让明文原片落盘。将假脱机阈值提高到上传上限，使允许范围
# 内的 multipart 一律留在内存（超限请求在入口处即被 Content-Length 拒绝）。
# 首选仍是原始 application/octet-stream 流式上传，完全不经表单解析器。
from starlette.formparsers import MultiPartParser
MultiPartParser.spool_max_size = MAX_UPLOAD_BYTES

from .crypto_stream import IntegrityError, decrypt_stream, encrypt_stream
from .inflight import InflightUploads
from .keyclient import KeyClient, KeyServiceError
from .metadata import (ImageAlreadyExists, IdempotentReplay, MetadataDB,
                       RetiringKey)
from .rotation import RotationWorker

db = MetadataDB(DB_PATH)
keys = KeyClient(KEY_SERVICE_URL, KEY_SERVICE_TOKEN)
inflight = InflightUploads()
worker: RotationWorker | None = None
main_loop: asyncio.AbstractEventLoop | None = None


def _remove_blob(path: str | None) -> None:
    if not path:
        return
    try:
        os.remove(path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# 生命周期：引导主密钥 -> 崩溃恢复（在途上传判失败/轮换接续）-> 启动后台线程
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker, main_loop
    os.makedirs(BLOB_DIR, exist_ok=True)
    main_loop = asyncio.get_running_loop()
    # 等待密钥服务就绪并确保存在当前主密钥（重启幂等）
    for attempt in range(10):
        try:
            await keys.ensure_bootstrap()
            break
        except KeyServiceError:
            await asyncio.sleep(1.0)
    # 崩溃恢复：上次 receiving 的上传一律失败，禁止"晚发布"依赖旧密钥；
    # 同时清理这些失败尝试留下的密文残片（单实例下它们不可能再被续传）。
    stale_blobs = db.mark_stale_receiving_failed()
    for path in stale_blobs:
        _remove_blob(path)
    if stale_blobs:
        print(f"[startup] {len(stale_blobs)} interrupted upload(s) marked "
              f"failed and purged")
    # 历史 failed 行（含轮换清退/发布被拒）的残片同样清理；仅删登记在
    # BLOB_DIR 内的那份路径，不影响同编号后续成功尝试（其 blob_path 已不同）。
    blob_root = os.path.realpath(BLOB_DIR) + os.sep
    for path in db.list_failed_blob_paths():
        real = os.path.realpath(path) if path else ""
        if real.startswith(blob_root):
            _remove_blob(real)
    # 崩溃对账：上次可能已在密钥服务切换了 MK、却没来得及建本地作业
    try:
        key_status = await keys.master_status()
        current_mk = key_status.get("current_key_id")
        for key in key_status.get("keys", []):
            if (key["key_id"] != current_mk
                    and key["state"] == "active"
                    and not db.has_rotation_for(key["key_id"])):
                job_id = db.create_rotation(
                    key["key_id"], current_mk,
                    db.count_under_key(key["key_id"], only_migratable=True))
                print(f"[startup] reconciled missing rotation job {job_id} "
                      f"for {key['key_id']}")
    except KeyServiceError as exc:
        print(f"[startup] rotation reconciliation skipped: {exc}")
    worker = RotationWorker(db, keys, main_loop, inflight)
    worker.start()
    yield
    worker.stop()
    await keys.aclose()
    db.close()


app = FastAPI(
    title="Microscopy Image Warehouse API",
    version="1.0.0",
    description="原片流式加密存取，每件独立 DEK；支持主密钥在线轮换与进度查询。",
    lifespan=lifespan,
)


def _key_error(exc: KeyServiceError) -> HTTPException:
    return HTTPException(status_code=exc.status_code,
                         detail={"code": exc.code, "message": exc.message})


# --------------------------------------------------------------------------
# 上传
# --------------------------------------------------------------------------
async def _stream_to_blob(request: Request, blob_path: str,
                          dek: bytes) -> dict[str, Any]:
    """读 HTTP 请求体 -> 分帧加密 -> 密文直接写盘（无明文临时文件）。"""
    writer = open(blob_path, "wb")  # 二进制密文文件
    loop = asyncio.get_running_loop()

    async def write(data: bytes):
        await loop.run_in_executor(None, writer.write, data)
        await loop.run_in_executor(None, writer.flush)

    try:
        stats = await encrypt_stream(request.stream(), dek, write)
    finally:
        await loop.run_in_executor(None, writer.close)
    return stats


async def _finalize_with_rebind(image_id: str, blob_path: str,
                                stats: dict[str, Any]) -> dict[str, Any]:
    """最终化原片：先确保其信封绑定到一把不会在轮换中被销毁的主密钥，
    再以"本次尝试仍待接收"为条件发布。

    改绑依据本地轮换记录 + 密钥服务当前主密钥：
      * 本行 MASTER_KEY 已被某次轮换登记为旧密钥 -> rewrap 到当前 MK；
        若该旧 MK 已销毁（极端窗口），rewrap 返回 410，判失败；
      * 连续轮换/迁移恰好发生：发布 SQL 自身再校验"不是任何轮换旧密钥"，
        被拒则回到循环重试改绑，绝不发布不可读原片。
    失败上传（已被轮换清退/进程重启判失败/被新尝试复用）一律不发布。
    """
    for _ in range(5):
        meta = db.get_image(image_id)
        if meta is None or meta["status"] != "receiving" \
                or meta["blob_path"] != blob_path:
            # 本次尝试已被判失败或被新尝试替换：不发布
            raise HTTPException(
                status_code=409,
                detail={"code": "upload_no_longer_active",
                        "message": "upload was retired before it could be "
                                   "finalized (timed out or interrupted)"})
        if db.key_is_retiring(meta["master_key_id"]):
            try:
                current = await keys.current_master()
            except KeyServiceError as exc:
                raise _key_error(exc)
            if not current or current == meta["master_key_id"]:
                # 没有更新的可用密钥（理论窗口）：按不可发布处理
                raise HTTPException(
                    status_code=409,
                    detail={"code": "no_active_master",
                            "message": "no active master key available for "
                                       "rebinding this upload"})
            try:
                res = await keys.rewrap(
                    meta["master_key_id"], meta["wrapped_dek"],
                    f"finalize:{image_id}:{blob_path}:{meta['master_key_id']}")
            except KeyServiceError as exc:
                if exc.status_code == 410:
                    # 再读一次：迁移线程可能已把本行改绑到新 MK，此时 410
                    # 只说明旧信封过时，上传仍可正常发布。
                    latest = db.get_image(image_id)
                    if latest and latest["status"] == "receiving" \
                            and latest["blob_path"] == blob_path \
                            and latest["master_key_id"] != meta["master_key_id"]:
                        continue
                    # 旧 MK 已销毁且该行信封未能迁移：绝不能晚发布不可读原片
                    raise HTTPException(
                        status_code=409,
                        detail={"code": "old_key_destroyed",
                                "message": "upload cannot be finalized; its key "
                                           "was rotated and destroyed before "
                                           "completion"})
                raise
            db.rewrap_row(image_id, meta["master_key_id"],
                          res["key_id"], res["wrapped_dek"])
            continue
        if db.finalize_image(image_id, blob_path, stats["plain_size"],
                             stats["enc_size"], stats["sha256"]):
            return db.get_image(image_id)
        # 发布被条件拒绝（期间轮换登记了该密钥/行被清退）：重新判断
    raise HTTPException(
        status_code=409,
        detail={"code": "upload_no_longer_active",
                "message": "upload could not be finalized consistently"})


def _check_content_length(request: Request):
    cl = request.headers.get("content-length")
    if cl is not None and int(cl) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, detail="upload exceeds MAX_UPLOAD_BYTES")


async def _begin_attempt(image_id: str, filename: str | None,
                         content_type: str | None,
                         idem_token: str | None) -> dict | None:
    """生成 DEK 并登记本次上传尝试；返回尝试上下文（含 DEK 响应、明文 DEK、
    blob 路径、被替换的旧残片路径）。

    抛出 ImageAlreadyExists / IdempotentReplay 由调用方翻译为 HTTP 响应。
    若 generate_dek 返回的主密钥恰已被某轮换作业登记为旧密钥（极小窗口），
    改用切换后的新 MK 重新生成 DEK 再登记，绝不把新行挂到即将销毁的密钥。
    每次尝试使用独立 blob 路径，使迟到的旧尝试无法发布/误删新尝试的数据。
    """
    for _ in range(3):
        try:
            dek_resp = await keys.generate_dek()
        except KeyServiceError as exc:
            raise _key_error(exc)
        dek = bytes.fromhex(dek_resp["dek"])
        blob_path = os.path.join(BLOB_DIR,
                                 f"{image_id}.{uuid.uuid4().hex}.msef")
        # 先登记为活跃再写库：轮换扫描与本次登记之间不再有"已建行但未登记
        # 活跃"的窗口，避免刚建立的上传被误当僵尸清退。
        inflight.add(image_id, blob_path)
        try:
            _, replaced = db.create_image(
                image_id, filename, content_type, dek_resp["key_id"],
                dek_resp["wrapped_dek"], blob_path, idem_token)
        except RetiringKey:
            del dek  # 该 MK 正在被清退：换新 MK 重新生成
            inflight.remove(image_id, blob_path)
            continue
        except Exception:
            inflight.remove(image_id, blob_path)
            raise
        return {"dek_resp": dek_resp, "dek": dek, "blob_path": blob_path,
                "replaced": replaced}
    raise HTTPException(
        status_code=503,
        detail={"code": "rotation_in_progress",
                "message": "master key rotation is in progress; retry upload"})


def _begin_error(exc: Exception, response: Response) -> dict:
    """把登记阶段的两类冲突翻译为与既有幂等语义一致的响应。"""
    if isinstance(exc, IdempotentReplay):
        existing = db.get_image(exc.image_id)
        response.status_code = 200
        return _replay_receipt(existing, response)
    raise HTTPException(
        status_code=409,
        detail={"code": "image_exists",
                "message": f"image already exists ({exc.status})"})


async def _run_upload(request: Request, response: Response, image_id: str,
                      attempt: dict) -> dict:
    """流式加密写盘 -> 绑定可用密钥 -> 条件发布 -> 回执。

    任一步失败都只清理"本次尝试"的密文残片；若该行已被新尝试复用或被
    轮换清退，条件更新不会误伤它。已判失败/已清退的上传即使随后传完也
    不会被发布（见 _finalize_with_rebind）。
    """
    dek, blob_path = attempt["dek"], attempt["blob_path"]
    # _begin_attempt 已把本次尝试登记为活跃；此处只负责在结束时注销。
    try:
        replaced = attempt["replaced"]
        if replaced and replaced != blob_path:
            _remove_blob(replaced)  # 被复用的旧失败尝试的残片
        stats = await _stream_to_blob(request, blob_path, dek)
        if stats["plain_size"] > MAX_UPLOAD_BYTES:
            raise HTTPException(413, detail="upload exceeds MAX_UPLOAD_BYTES")
        final = await _finalize_with_rebind(image_id, blob_path, stats)
    except HTTPException:
        db.fail_image(image_id, blob_path, "upload rejected")
        # blob_path 是本次尝试独占的路径，任何失败都可安全清理；
        # fail_image 的条件更新保证不会改动已发布/已被新尝试复用的行。
        _remove_blob(blob_path)
        raise
    except Exception as exc:  # 写入失败/发布被拒：判失败并清理密文残片
        db.fail_image(image_id, blob_path, f"upload failed: {exc!r}")
        _remove_blob(blob_path)
        raise HTTPException(status_code=502,
                            detail=f"upload failed: {exc!r}") from exc
    finally:
        inflight.remove(image_id, blob_path)
    return {"image_id": image_id, "status": "ready",
            "size": stats["plain_size"], "sha256": stats["sha256"],
            "master_key_id": final["master_key_id"]}


def _replay_receipt(existing: dict, response: Response) -> dict:
    response.status_code = 200
    return {"image_id": existing["image_id"], "status": existing["status"],
            "idempotent": True}


@app.post("/images", status_code=201,
          summary="上传原片（流式加密；支持 X-Idempotency-Token 幂等）")
async def upload_image(request: Request, response: Response,
                       x_idempotency_token: str | None = Header(default=None),
                       x_filename: str | None = Header(default=None),
                       x_content_type: str | None = Header(default=None)):
    _check_content_length(request)
    # 幂等重放：直接返回既有回执，不重复入湖
    if x_idempotency_token:
        existing = db.get_by_token(x_idempotency_token)
        if existing:
            return _replay_receipt(existing, response)
    image_id = "img-" + uuid.uuid4().hex
    try:
        attempt = await _begin_attempt(
            image_id, x_filename,
            x_content_type or request.headers.get("content-type"),
            x_idempotency_token)
    except (ImageAlreadyExists, IdempotentReplay) as exc:
        return _begin_error(exc, response)
    try:
        return await _run_upload(request, response, image_id, attempt)
    finally:
        del attempt  # 尽快丢弃明文 DEK 引用


@app.put("/images/{image_id}", status_code=201,
         summary="按调用方指定编号上传原片")
async def upload_image_named(image_id: str, request: Request, response: Response,
                             x_idempotency_token: str | None = Header(default=None),
                             x_filename: str | None = Header(default=None),
                             x_content_type: str | None = Header(default=None)):
    if not image_id or len(image_id) > 128 or "/" in image_id or ".." in image_id:
        raise HTTPException(400, detail="invalid image_id")
    _check_content_length(request)
    if x_idempotency_token:
        existing = db.get_by_token(x_idempotency_token)
        if existing:
            return _replay_receipt(existing, response)
    try:
        attempt = await _begin_attempt(
            image_id, x_filename,
            x_content_type or request.headers.get("content-type"),
            x_idempotency_token)
    except (ImageAlreadyExists, IdempotentReplay) as exc:
        return _begin_error(exc, response)
    try:
        return await _run_upload(request, response, image_id, attempt)
    finally:
        del attempt


# --------------------------------------------------------------------------
# 下载 / 查询
# --------------------------------------------------------------------------
def _cipher_chunks(path: str):
    async def gen():
        loop = asyncio.get_running_loop()
        f = await loop.run_in_executor(None, open, path, "rb")
        try:
            while True:
                chunk = await loop.run_in_executor(None, f.read, 1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            await loop.run_in_executor(None, f.close)
    return gen()


@app.get("/images/{image_id}", summary="按编号下载原片（流式解密，逐帧验签）")
async def download_image(image_id: str):
    meta = db.get_image(image_id)
    if meta is None:
        raise HTTPException(404, detail="image not found")
    if meta["status"] != "ready":
        raise HTTPException(409, detail=f"image is {meta['status']}")
    if not os.path.exists(meta["blob_path"]):
        raise HTTPException(410, detail="encrypted blob missing on storage")
    try:
        # 解包一次：明文 DEK 只在本次请求内存；随后即使密钥服务变慢或
        # 主密钥被销毁，已解包的慢下载也能完整读完（解密不再依赖密钥服务）。
        dek = await keys.unwrap(meta["master_key_id"], meta["wrapped_dek"])
    except KeyServiceError as exc:
        raise _key_error(exc)

    async def plain_iter():
        local_dek = dek  # 局部别名；生成器结束后随帧栈释放，不留长生命周期引用
        try:
            async for chunk in decrypt_stream(
                    _cipher_chunks(meta["blob_path"]), local_dek,
                    expected_sha256=meta["sha256"]):
                yield chunk
        except IntegrityError as exc:
            raise HTTPException(500, detail=f"integrity check failed: {exc}")
        finally:
            del local_dek

    headers = {"X-Image-Id": image_id,
               "X-SHA256": meta["sha256"] or ""}
    if meta["filename"]:
        headers["Content-Disposition"] = (
            f'attachment; filename="{meta["filename"]}"')
    return StreamingResponse(
        plain_iter(),
        media_type=meta["content_type"] or "application/octet-stream",
        headers=headers)


@app.get("/images", summary="列出原片元数据")
async def list_images(limit: int = 100, offset: int = 0):
    return {"items": db.list_images(min(limit, 500), offset)}


@app.get("/images/{image_id}/meta", summary="单件原片元数据/状态")
async def image_meta(image_id: str):
    meta = db.get_image(image_id)
    if meta is None:
        raise HTTPException(404, detail="image not found")
    meta.pop("wrapped_dek", None)
    return meta


# --------------------------------------------------------------------------
# 轮换
# --------------------------------------------------------------------------
class RotationRequest(BaseModel):
    confirm: bool = True


@app.post("/rotations", status_code=202,
          summary="发起主密钥轮换（迁移信封后销毁旧 MK；未完拒绝新轮换）")
async def create_rotation(_: RotationRequest):
    active = db.active_rotation()
    if active is not None:
        raise HTTPException(
            409, detail={"code": "rotation_in_progress",
                         "job_id": active["job_id"], "state": active["state"]})
    try:
        rot = await keys.rotate_master()  # 新入湖立即改用新 MK
        old_key, new_key = rot["old_key_id"], rot["new_key_id"]
        total = (db.count_under_key(old_key, only_migratable=True)
                 if old_key else 0)
        try:
            job_id = db.create_rotation(old_key, new_key, total)
        except RuntimeError:
            # 并发窗口：另一请求已先建单并完成了 MK 切换。以既有作业为准，
            # 不启动第二个轮换。
            active = db.active_rotation()
            if active is None:
                raise
            raise HTTPException(
                409, detail={"code": "rotation_in_progress",
                             "job_id": active["job_id"],
                             "state": active["state"]})
    except KeyServiceError as exc:
        raise _key_error(exc)
    return {"job_id": job_id, "state": "migrating", "old_key_id": old_key,
            "new_key_id": new_key, "total_to_migrate": total}


@app.get("/rotations/latest", summary="查询最近一次轮换进度")
async def latest_rotation():
    job = db.latest_rotation()
    if job is None:
        return {"message": "no rotation has ever run"}
    return _rotation_view(job)


@app.get("/rotations/{job_id}", summary="按作业号查询轮换进度")
async def rotation_status(job_id: str):
    job = db.get_rotation(job_id)
    if job is None:
        raise HTTPException(404, detail="rotation job not found")
    return _rotation_view(job)


def _rotation_view(job: dict) -> dict:
    total = max(job["total"], job["migrated"] + job["failed"], 1)
    pct = round(100.0 * (job["migrated"] + job["failed"]) / total, 2)
    return {**{k: v for k, v in job.items()}, "progress_percent": pct}


@app.get("/keys/status", summary="密钥视角状态（代理密钥服务只读接口）")
async def key_status():
    try:
        return await keys.master_status()
    except KeyServiceError as exc:
        raise _key_error(exc)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "image-api", "time": time.time()}
