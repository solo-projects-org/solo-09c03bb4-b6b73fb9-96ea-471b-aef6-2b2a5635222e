"""本进程在途上传登记表。

用途：轮换清退时区分两种 receiving 行——
  * 本进程正在服务、可能很慢但仍能传完的上传：绝不能仅因"慢"就判失败，
    只把它的信封改绑当前主密钥即可（DEK 不变，上传可继续）；
  * 已无对应请求的 receiving 行（崩溃遗留/异常悬挂）：超过阈值才判失败，
    并清理其密文残片。

键含 blob_path（每次上传尝试唯一），因此同一编号的后续尝试不会让旧尝试
被误认为活跃。
"""
from __future__ import annotations

import threading


class InflightUploads:
    def __init__(self):
        self._lock = threading.Lock()
        self._active: set[tuple[str, str]] = set()

    def add(self, image_id: str, blob_path: str) -> None:
        with self._lock:
            self._active.add((image_id, blob_path))

    def remove(self, image_id: str, blob_path: str) -> None:
        with self._lock:
            self._active.discard((image_id, blob_path))

    def is_active(self, image_id: str, blob_path: str) -> bool:
        with self._lock:
            return (image_id, blob_path) in self._active
