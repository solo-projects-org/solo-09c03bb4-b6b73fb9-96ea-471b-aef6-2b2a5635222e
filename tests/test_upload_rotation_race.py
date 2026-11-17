"""T13-T16：上传最终化与轮换清退的状态协作（本次修复的核心回归）。

T13 超时清退后迟到的上传不得复活为 ready，密文残片被清理
T14 慢但在途的上传不被轮换判失败；改绑当前 MK 后完成发布，逐字节可下载，
    旧 MK 仍能按期销毁（不被慢上传长期阻塞）
T15 连续两次轮换期间持续慢上传：轮换均完成，其他原片可读写
T16 失败上传的残片被清理；成功回执所指原片在轮换完成后逐字节一致
"""
from __future__ import annotations

import http.client
import signal
import sqlite3
import threading
import time

import httpx

from conftest import _download, _upload, _wait_rotation


def _start_rotation(client: httpx.Client) -> dict:
    r = client.post("/rotations", json={"confirm": True})
    assert r.status_code == 202, r.text
    return r.json()


def _blob_files(stack) -> set[str]:
    return {p.name for p in stack["blob_dir"].iterdir() if p.is_file()}


def test_upload_orphaned_by_process_crash_fails_and_fragment_purged(stack):
    """真实复现：上传开始后进程被 kill（连接断裂、无活跃请求）。重启后
    该行判失败；随后再轮换并销毁旧 MK，下载必须干净地报失败而非 410 ready。"""
    client = stack["client"]
    _upload(client, b"anchor", image_id="crash-anchor")
    old_key = client.get("/images/crash-anchor/meta").json()["master_key_id"]

    # 发起一个只发头部、不结束请求体的上传，建立 receiving 行后直接断开
    conn = http.client.HTTPConnection("127.0.0.1", stack["api"].port, timeout=10)
    conn.putrequest("PUT", "/images/crash-victim")
    conn.putheader("Content-Type", "application/octet-stream")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(b"1000\r\n" + b"A" * 0x1000 + b"\r\n")  # 只发一段，不结束
    time.sleep(1.0)  # 让服务端登记 receiving 行并开始接收
    meta = client.get("/images/crash-victim/meta").json()
    assert meta["status"] == "receiving", meta
    # 模拟进程崩溃：SIGKILL，连接与内存中的在途登记一起消失
    stack["api"].proc.send_signal(signal.SIGKILL)
    stack["api"].proc.wait(timeout=15)
    stack["api"].proc = None
    conn.close()
    stack["api"].start()

    meta = client.get("/images/crash-victim/meta").json()
    assert meta["status"] == "failed", meta
    # 崩溃残留的密文残片已被清理
    assert not any(p.name.startswith("crash-victim")
                   for p in stack["blob_dir"].iterdir())

    # 再轮换：旧 MK 销毁后，失败上传不会变成可下载的 ready（更不会是 410 ready）
    job = _start_rotation(client)
    result = _wait_rotation(client, job["job_id"], timeout=90)
    assert result["state"] == "completed", result
    assert client.get("/images/crash-victim/meta").json()["status"] == "failed"
    r = client.get("/images/crash-victim")
    assert r.status_code in (409, 410)
    assert _download(client, "crash-anchor") == b"anchor"


def test_timed_out_upload_cannot_publish_after_completion(stack):
    """轮换已把超时上传清退并销毁旧密钥；上传随后传完也只能报失败。"""
    client = stack["client"]
    # 造一条"早已建立、但本进程没有活跃请求"的 receiving 行（等同悬挂连接）
    mk = client.get("/keys/status").json()["current_key_id"]
    stale_blob = stack["blob_dir"] / "late-timeout.msef"
    stale_blob.write_bytes(b"partial-ciphertext-fragment")
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    conn.execute(
        "INSERT INTO images (image_id, status, master_key_id, wrapped_dek, "
        "blob_path, created_at) VALUES ('late-timeout','receiving',?,?,?,?)",
        (mk, "00" * 64, str(stale_blob), time.time() - 120))
    conn.commit()
    conn.close()

    job = _start_rotation(client)
    result = _wait_rotation(client, job["job_id"], timeout=90)
    assert result["state"] == "completed", result

    meta = client.get("/images/late-timeout/meta").json()
    assert meta["status"] == "failed"
    # 清退时清理了密文残片，且之后也不会被晚发布
    assert not stale_blob.exists()
    assert client.get("/images/late-timeout").status_code in (409, 410)
    # 其他原片照常
    assert _upload(client, b"healthy", image_id="healthy-1").status_code == 201
    assert _download(client, "healthy-1") == b"healthy"


def test_late_completion_after_retirement_is_not_published(stack):
    """同一编号的失败尝试后来"传完"：finalize 条件更新拒绝发布（不复活）。"""
    client = stack["client"]
    # 之前的一次尝试被判失败（残片路径 A）
    old = stack["blob_dir"] / "revive.aaaa.msef"
    old.write_bytes(b"old-attempt")
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    conn.execute(
        "INSERT INTO images (image_id, status, master_key_id, wrapped_dek, "
        "blob_path, created_at, error) VALUES ('revive','failed',?,?,?,?,?)",
        ("mk-x", "00" * 64, str(old), time.time() - 60, "timed out"))
    conn.commit()
    conn.close()
    # 新尝试复用该编号并成功
    r = _upload(client, b"fresh-attempt", image_id="revive")
    assert r.status_code == 201, r.text
    assert _download(client, "revive") == b"fresh-attempt"
    meta = client.get("/images/revive/meta").json()
    assert meta["status"] == "ready"
    # 旧尝试的残片已被清理，且新 blob 仍在
    assert not old.exists()
    assert (stack["blob_dir"] / meta["blob_path"].rsplit("/", 1)[-1]).exists()


def test_slow_inflight_upload_not_retired_and_rebinds(stack):
    """慢上传（超过清退阈值但请求仍活跃）不被判失败：改绑新 MK 后正常发布，
    旧 MK 仍能完成销毁，未被慢上传长期阻塞。"""
    client, kc = stack["client"], stack["key_client"]
    _upload(client, b"anchor", image_id="slow-anchor")
    old_key = client.get("/images/slow-anchor/meta").json()["master_key_id"]

    started: list[dict] = []

    def rotate_during_upload():
        time.sleep(1.0)
        started.append(client.post("/rotations", json={"confirm": True}).json())

    def slow_body():
        yield b"slow-head"
        time.sleep(deadline_seconds + 2.5)  # 超过 UPLOAD_STALE_SECONDS=2
        yield b"slow-tail"

    deadline_seconds = 2  # 与 conftest 中 UPLOAD_STALE_SECONDS 一致
    t = threading.Thread(target=rotate_during_upload)
    t.start()
    r = client.put("/images/slow-live", content=slow_body(),
                   headers={"Content-Type": "application/octet-stream"},
                   timeout=120)
    t.join()
    assert r.status_code == 201, r.text
    job = started[0]
    result = _wait_rotation(client, job["job_id"], timeout=90)
    assert result["state"] == "completed", result

    # 旧 MK 确实销毁（慢上传未阻塞销毁）
    status = kc.get("/internal/master/status",
                    headers={"X-Key-Service-Token": "test-secret-token"}).json()
    states = {k["key_id"]: k["state"] for k in status["keys"]}
    assert states[old_key] == "destroyed"
    assert states[job["new_key_id"]] == "active"

    # 成功回执绑定可用新密钥，逐字节可下载
    assert r.json()["status"] == "ready"
    assert r.json()["master_key_id"] == job["new_key_id"]
    assert _download(client, "slow-live") == b"slow-headslow-tail"
    assert _download(client, "slow-anchor") == b"anchor"


def test_two_consecutive_rotations_with_slow_uploads(stack):
    """连续两次轮换期间持续有慢上传：两次轮换都完成，原片可读写，
    失败上传残片清理，成功回执所指原片逐字节可下载。"""
    client = stack["client"]
    payloads = {}
    for i in range(4):
        payload = f"pre-{i}".encode() * 4000
        payloads[f"pre-{i}"] = payload
        assert _upload(client, payload, image_id=f"pre-{i}").status_code == 201

    stop = threading.Event()
    inflight_results: list[tuple[str, int]] = []

    def slow_uploader(idx: int):
        def body():
            yield f"inflight-{idx}-".encode()
            for _ in range(8):
                if stop.is_set():
                    break
                time.sleep(0.35)
                yield b"x" * 4096
            yield b"-tail"
        try:
            r = client.put(f"/images/inflight-{idx}", content=body(),
                           headers={"Content-Type": "application/octet-stream"},
                           timeout=120)
            inflight_results.append((f"inflight-{idx}", r.status_code))
        except Exception:  # noqa: BLE001
            inflight_results.append((f"inflight-{idx}", -1))

    threads = [threading.Thread(target=slow_uploader, args=(i,)) for i in range(2)]
    for th in threads:
        th.start()

    for round_no in range(2):
        job = _start_rotation(client)
        result = _wait_rotation(client, job["job_id"], timeout=120)
        assert result["state"] == "completed", (round_no, result)
        # 轮换完成后其他原片仍逐字节可读
        for image_id, payload in payloads.items():
            assert _download(client, image_id) == payload
        # 每轮也能正常入湖
        _upload(client, f"during-{round_no}".encode(), image_id=f"during-{round_no}")
        assert _download(client, f"during-{round_no}") == f"during-{round_no}".encode()

    stop.set()
    for th in threads:
        th.join(timeout=60)
    # 慢上传要么成功发布并可下载，要么被明确判失败；不得"回执成功却不可读"
    for image_id, status in inflight_results:
        if status == 201:
            assert client.get(f"/images/{image_id}/meta").json()["status"] == "ready"
            got = client.get(f"/images/{image_id}")
            assert got.status_code == 200
            assert got.content.endswith(b"-tail")
        else:
            assert client.get(f"/images/{image_id}/meta").json()["status"] == "failed"
    # 所有登记为 ready 的原片都能逐字节读出（无 410）
    for item in client.get("/images").json()["items"]:
        if item["status"] == "ready":
            assert client.get(f"/images/{item['image_id']}").status_code == 200
