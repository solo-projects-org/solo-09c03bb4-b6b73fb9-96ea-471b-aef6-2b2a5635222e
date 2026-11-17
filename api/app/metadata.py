"""API 元数据库（SQLite，WAL）。

只存：原片元数据、密文 blob 路径、信封 DEK（密文）、主密钥 id、状态。
绝不存：明文 DEK、明文原片、主密钥材料。
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS images (
    image_id        TEXT PRIMARY KEY,
    filename        TEXT,
    content_type    TEXT,
    status          TEXT NOT NULL CHECK (status IN
                        ('receiving','ready','failed')),
    master_key_id   TEXT NOT NULL,
    wrapped_dek     TEXT NOT NULL,           -- 十六进制信封，始终为密文
    blob_path       TEXT NOT NULL,
    plain_size      INTEGER,
    enc_size        INTEGER,
    sha256          TEXT,
    idem_token      TEXT UNIQUE,
    error           TEXT,
    created_at      REAL NOT NULL,
    finalized_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_images_mk ON images(master_key_id);
CREATE INDEX IF NOT EXISTS idx_images_status ON images(status);

CREATE TABLE IF NOT EXISTS rotation_jobs (
    job_id          TEXT PRIMARY KEY,
    state           TEXT NOT NULL CHECK (state IN
                        ('migrating','destroying','completed','failed')),
    old_key_id      TEXT NOT NULL,
    new_key_id      TEXT NOT NULL,
    total           INTEGER NOT NULL DEFAULT 0,
    migrated        INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    started_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    finished_at     REAL
);
"""

TERMINAL_STATES = ("completed", "failed")


class ImageAlreadyExists(Exception):
    """同名原片仍处于 receiving/ready：不接受覆盖。"""

    def __init__(self, status: str):
        super().__init__(f"image already exists ({status})")
        self.status = status


class IdempotentReplay(Exception):
    """同一幂等令牌已登记过，返回既有原片。"""

    def __init__(self, image_id: str):
        super().__init__(image_id)
        self.image_id = image_id


class RetiringKey(Exception):
    """准备登记的信封绑定到了一把已进入轮换清退的主密钥。

    若允许登记，行可能在"销毁前零残留核验"之后才写入，从而被晚发布到
    随即被销毁的密钥上。调用方应改用"生成时此刻的当前 MK"重新生成 DEK。
    """

    def __init__(self, key_id: str):
        super().__init__(f"master key {key_id} is being retired")
        self.key_id = key_id


class MetadataDB:
    """每线程独立连接（SQLite 连接不跨线程复用），写操作串行化。"""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._write_lock = threading.RLock()
        self._local = threading.local()
        conn = self._connect()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._connect()
            self._local.conn = c
        return c

    # ---- 原片 -----------------------------------------------------------
    def create_image(self, image_id: str, filename: str | None,
                     content_type: str | None, master_key_id: str,
                     wrapped_dek: str, blob_path: str,
                     idem_token: str | None) -> tuple[str, str | None]:
        """原子地登记 receiving 行；返回 (image_id, 被替换的旧残片路径或 None)。

        每次上传尝试使用独立 blob 路径，故行内的 blob_path 即"本次尝试"的
        身份：轮换清退/最终化都按 (image_id, blob_path) 做条件更新，迟到的
        旧尝试既不能发布、也不能误伤复用同一编号的新尝试。

        失败上传会释放幂等令牌并保留 failed 行；同一令牌/同一编号的重试原地
        复用该行（重置为 receiving、换新 DEK 与 blob 路径），而不是插入新行。
        目标编号当前是 receiving/ready 且不属于同一幂等令牌时抛
        ImageAlreadyExists；master_key_id 已被轮换作业登记为旧密钥时抛
        RetiringKey（同一事务内判定，与轮换建单/销毁核验串行化）。
        """
        with self._write_lock:
            if idem_token:
                existing = self.conn.execute(
                    "SELECT image_id FROM images WHERE idem_token=?",
                    (idem_token,)).fetchone()
                if existing:
                    raise IdempotentReplay(existing["image_id"])
            if self.conn.execute(
                    "SELECT 1 FROM rotation_jobs WHERE old_key_id=? LIMIT 1",
                    (master_key_id,)).fetchone() is not None:
                raise RetiringKey(master_key_id)
            row = self.conn.execute(
                "SELECT image_id, status, idem_token, blob_path FROM images "
                "WHERE image_id=?", (image_id,)).fetchone()
            replaced: str | None = None
            if row is not None:
                same_token = (idem_token is not None
                              and row["idem_token"] == idem_token)
                if row["status"] == "ready":
                    # 已发布：同令牌按幂等重放，其他一律拒绝覆盖
                    if same_token:
                        raise IdempotentReplay(image_id)
                    raise ImageAlreadyExists(row["status"])
                if row["status"] == "receiving":
                    # 另一个仍在进行中的尝试占用该行：同令牌重放，否则拒绝
                    if same_token:
                        raise IdempotentReplay(image_id)
                    raise ImageAlreadyExists(row["status"])
                replaced = row["blob_path"]  # failed 行：本次尝试接管
            now = time.time()
            try:
                if row is not None:
                    # 复用失败的旧行；旧残片路径交给调用方清理
                    self.conn.execute(
                        "UPDATE images SET filename=?, content_type=?, "
                        "status='receiving', master_key_id=?, wrapped_dek=?, "
                        "blob_path=?, plain_size=NULL, enc_size=NULL, "
                        "sha256=NULL, idem_token=?, error=NULL, created_at=?, "
                        "finalized_at=NULL WHERE image_id=?",
                        (filename, content_type, master_key_id, wrapped_dek,
                         blob_path, idem_token, now, image_id))
                else:
                    self.conn.execute(
                        "INSERT INTO images (image_id, filename, content_type, "
                        "status, master_key_id, wrapped_dek, blob_path, "
                        "idem_token, created_at) "
                        "VALUES (?,?,?, 'receiving', ?,?,?,?,?)",
                        (image_id, filename, content_type, master_key_id,
                         wrapped_dek, blob_path, idem_token, now))
            except sqlite3.IntegrityError:
                # 并发同令牌请求抢先插入：按幂等重放
                existing = self.conn.execute(
                    "SELECT image_id FROM images WHERE idem_token=?",
                    (idem_token,)).fetchone()
                self.conn.rollback()
                if existing:
                    raise IdempotentReplay(existing["image_id"])
                raise
            self.conn.commit()
            return image_id, replaced

    def get_image(self, image_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE image_id=?", (image_id,)).fetchone()
        return dict(row) if row else None

    def get_by_token(self, idem_token: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE idem_token=?", (idem_token,)).fetchone()
        return dict(row) if row else None

    def finalize_image(self, image_id: str, blob_path: str, plain_size: int,
                       enc_size: int, sha256: str) -> bool:
        """发布原片：仅当该行仍是"本次上传尝试"且仍待接收时成功。

        两重条件缺一不可：
          1. status='receiving' 且 blob_path 等于本次尝试的路径：轮换超时
             清退或进程重启可能已把该行判失败，甚至已被同一编号的新尝试
             复用；此时"已判失败的上传即使后来传完也不能重新发布"；
          2. 该行绑定的主密钥不是任何轮换作业的旧密钥。"可完成的发布"必须
             先由调用方改绑到可用密钥——这条 SQL 在写锁内与轮换的
             "零残留核验"、作业建单串行化，保证不会发布一把随后被销毁的
             密钥下的原片（否则登记 ready、下载 410）。
        返回 False 表示发布被拒，调用方必须清理本次尝试的密文残片并报失败。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET status='ready', plain_size=?, enc_size=?, "
                "sha256=?, finalized_at=?, error=NULL "
                "WHERE image_id=? AND blob_path=? AND status='receiving' "
                "AND NOT EXISTS (SELECT 1 FROM rotation_jobs rj "
                "                WHERE rj.old_key_id = images.master_key_id)",
                (plain_size, enc_size, sha256, time.time(), image_id, blob_path))
            self.conn.commit()
            return cur.rowcount > 0

    def key_is_retiring(self, key_id: str) -> bool:
        """该主密钥是否已被任一轮换作业登记为旧密钥（不论作业当前状态）。

        一旦某密钥成为某次轮换的旧密钥，新发布就不得再绑定它：作业可能
        正在销毁、已销毁或因故障停在中间。迁移仍可正常 rewrap 它。
        """
        return self.conn.execute(
            "SELECT 1 FROM rotation_jobs WHERE old_key_id=? LIMIT 1",
            (key_id,)).fetchone() is not None

    def fail_image(self, image_id: str, blob_path: str, error: str) -> bool:
        """把本次尝试判失败（仅对仍属于该尝试的 receiving 行生效）。

        返回 False 说明该行已被发布、或已被新的尝试复用——不得再改动它，
        也不得删除新尝试的 blob。
        """
        with self._write_lock:
            # 失败行释放幂等令牌，允许客户端用同一令牌重新发起上传
            cur = self.conn.execute(
                "UPDATE images SET status='failed', error=?, finalized_at=?, "
                "idem_token=NULL WHERE image_id=? AND blob_path=? "
                "AND status='receiving'",
                (error[:500], time.time(), image_id, blob_path))
            self.conn.commit()
            return cur.rowcount > 0

    def retire_stale_receiving(self, image_id: str, blob_path: str,
                               error: str) -> str | None:
        """批量/轮换清退僵死在途上传：仅当仍是同一尝试的 receiving 行。

        返回被清退尝试的 blob_path（供清理密文残片），否则 None。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET status='failed', error=?, finalized_at=?, "
                "idem_token=NULL WHERE image_id=? AND blob_path=? "
                "AND status='receiving'",
                (error[:500], time.time(), image_id, blob_path))
            self.conn.commit()
            return blob_path if cur.rowcount > 0 else None

    def list_images(self, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self.conn.execute(
            "SELECT image_id, filename, status, master_key_id, plain_size, "
            "sha256, created_at, finalized_at FROM images "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def distinct_key_ids(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT master_key_id FROM images").fetchall()
        return [r["master_key_id"] for r in rows]

    def list_failed_blob_paths(self) -> list[str]:
        """所有 failed 行登记的 blob 路径（供启动时清理残片）。"""
        rows = self.conn.execute(
            "SELECT blob_path FROM images WHERE status='failed'").fetchall()
        return [r["blob_path"] for r in rows]

    def count_under_key(self, key_id: str,
                        only_migratable: bool = False) -> int:
        sql = "SELECT COUNT(*) AS n FROM images WHERE master_key_id=?"
        if only_migratable:
            # 仅统计会阻塞销毁的行：ready（必须 rewrap）与在途 receiving；
            # failed 行永不会被下载，无需有效信封，不阻塞销毁。
            sql += " AND status IN ('ready','receiving')"
        return self.conn.execute(sql, (key_id,)).fetchone()["n"]

    def iter_under_key(self, key_id: str) -> Iterator[dict]:
        rows = self.conn.execute(
            "SELECT * FROM images WHERE master_key_id=? "
            "AND status IN ('ready','receiving') ORDER BY created_at",
            (key_id,)).fetchall()
        for r in rows:
            yield dict(r)

    def rewrap_row(self, image_id: str, expect_old_key: str,
                   new_key_id: str, new_wrapped: str) -> bool:
        """条件更新：仅当该行仍绑定旧 MK 时改包，返回是否实际更新。

        这样迁移与"迟到的在途上传最终化"互不覆盖：后者若已自行改绑新 MK，
        迁移跳过它即可。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET master_key_id=?, wrapped_dek=? "
                "WHERE image_id=? AND master_key_id=?",
                (new_key_id, new_wrapped, image_id, expect_old_key))
            self.conn.commit()
            return cur.rowcount > 0

    def mark_stale_receiving_failed(self) -> list[str]:
        """进程重启后，所有 receiving 行都是上次崩溃的在途上传，判失败并
        返回其 blob 路径供清理密文残片（不允许晚发布）。"""
        with self._write_lock:
            rows = self.conn.execute(
                "SELECT blob_path FROM images WHERE status='receiving'").fetchall()
            self.conn.execute(
                "UPDATE images SET status='failed', "
                "error='interrupted by service restart', finalized_at=? "
                "WHERE status='receiving'", (time.time(),))
            self.conn.commit()
            return [r["blob_path"] for r in rows]

    # ---- 轮换作业 -------------------------------------------------------
    def active_rotation(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE state NOT IN ('completed','failed')"
        ).fetchone()
        return dict(row) if row else None

    def create_rotation(self, old_key_id: str, new_key_id: str,
                        total: int) -> str:
        with self._write_lock:
            if self.active_rotation() is not None:
                raise RuntimeError("rotation already in progress")
            job_id = "rot-" + uuid.uuid4().hex
            now = time.time()
            self.conn.execute(
                "INSERT INTO rotation_jobs (job_id, state, old_key_id, "
                "new_key_id, total, migrated, failed, started_at, updated_at) "
                "VALUES (?, 'migrating', ?,?,?, 0, 0, ?, ?)",
                (job_id, old_key_id, new_key_id, total, now, now))
            self.conn.commit()
            return job_id

    def has_rotation_for(self, old_key_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM rotation_jobs WHERE old_key_id=? LIMIT 1",
            (old_key_id,)).fetchone() is not None

    def get_rotation(self, job_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def latest_rotation(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def bump_rotation(self, job_id: str, migrated: int = 0, failed: int = 0,
                      state: str | None = None, error: str | None = None) -> None:
        with self._write_lock:
            sets = ["updated_at=?"]
            params: list[Any] = [time.time()]
            if migrated:
                sets.append("migrated = migrated + ?")
                params.append(migrated)
            if failed:
                sets.append("failed = failed + ?")
                params.append(failed)
            if state:
                sets.append("state=?")
                params.append(state)
            if error is not None:
                sets.append("error=?")
                params.append(error[:500])
            if state in TERMINAL_STATES:
                sets.append("finished_at=?")
                params.append(time.time())
            params.append(job_id)
            self.conn.execute(
                f"UPDATE rotation_jobs SET {', '.join(sets)} WHERE job_id=?",
                params)
            self.conn.commit()

    def close(self):
        c = getattr(self._local, "conn", None)
        if c:
            c.close()
