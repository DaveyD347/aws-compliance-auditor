"""Thread-safe, cached boto3 client factory."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

import boto3
from botocore.config import Config

# Adaptive retries back off automatically on throttling (common when scanning many regions).
DEFAULT_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10}, user_agent_extra="aws-compliance-auditor")


class ClientFactory:
    """Creates one client per (service, region) and memoises expensive account-wide lookups.

    boto3 *sessions* are not thread-safe but *clients* are, so client creation is
    serialised behind a lock and the resulting clients are shared across worker threads.
    """

    def __init__(self, session: boto3.session.Session | None = None, config: Config = DEFAULT_CONFIG) -> None:
        self.session = session or boto3.session.Session()
        self.config = config
        self._clients: dict[tuple[str, str], Any] = {}
        self._memo: dict[str, Any] = {}
        self._lock = threading.RLock()

    def get(self, service: str, region: str):
        key = (service, region)
        with self._lock:
            if key not in self._clients:
                self._clients[key] = self.session.client(service, region_name=region, config=self.config)
            return self._clients[key]

    def memo(self, key: str, factory: Callable[[], Any]) -> Any:
        with self._lock:
            if key not in self._memo:
                self._memo[key] = factory()
            return self._memo[key]

    def account_id(self) -> str:
        return self.memo("sts:account", lambda: self.get("sts", "us-east-1").get_caller_identity()["Account"])

    def enabled_regions(self, home_region: str = "us-east-1") -> list[str]:
        resp = self.get("ec2", home_region).describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
