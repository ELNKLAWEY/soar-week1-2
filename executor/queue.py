"""Action queues: Redis Streams (production) and in-memory (unit tests / demo).

Set SENTINEL_ACTION_QUEUE=redis (and REDIS_URL) to use the `actions` stream with
consumer group `executor` (XADD / XREADGROUP / XACK, bad messages go to `actions:dlq`).
"""

from __future__ import annotations

import json
import os
from collections import deque
from dataclasses import dataclass, field
from uuid import uuid4

import redis
from pydantic import ValidationError

from common.schemas.actions import ActionRequest, ActionResult


@dataclass
class QueuedAction:
    """Envelope around an ActionRequest (mock stream message)."""

    message_id: str
    request: ActionRequest
    acked: bool = False


@dataclass
class InMemoryActionQueue:
    """Simple FIFO queue with ack semantics for the executor consumer."""

    _items: deque[QueuedAction] = field(default_factory=deque)
    _inflight: dict[str, QueuedAction] = field(default_factory=dict)

    def enqueue(self, request: ActionRequest) -> str:
        mid = f"mem-{uuid4().hex[:12]}"
        self._items.append(QueuedAction(message_id=mid, request=request))
        return mid

    def enqueue_many(self, requests: list[ActionRequest]) -> list[str]:
        return [self.enqueue(r) for r in requests]

    def __len__(self) -> int:
        return len(self._items)

    def consume(self, count: int = 1) -> list[QueuedAction]:
        out: list[QueuedAction] = []
        for _ in range(min(count, len(self._items))):
            item = self._items.popleft()
            self._inflight[item.message_id] = item
            out.append(item)
        return out

    def ack(self, message_id: str) -> bool:
        item = self._inflight.pop(message_id, None)
        if item is None:
            return False
        item.acked = True
        return True


class RedisActionQueue:
    """Redis Streams consumer group with the same interface as InMemoryActionQueue."""

    def __init__(
        self,
        client: redis.Redis,
        stream: str = "actions",
        group: str = "executor",
        consumer: str = "executor-1",
        block_ms: int | None = None,
        maxlen: int = 100_000,
    ) -> None:
        self.r = client
        self.stream = stream
        self.group = group
        self.consumer = consumer
        self.block_ms = block_ms
        self.maxlen = maxlen
        try:
            client.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def enqueue(self, request: ActionRequest) -> str:
        return self.r.xadd(
            self.stream,
            {"request": request.model_dump_json()},
            maxlen=self.maxlen,
            approximate=True,
        )

    def enqueue_many(self, requests: list[ActionRequest]) -> list[str]:
        return [self.enqueue(r) for r in requests]

    def __len__(self) -> int:
        """Messages not yet delivered to the group."""
        for g in self.r.xinfo_groups(self.stream):
            if g["name"] == self.group:
                return int(g.get("lag") or 0)
        return 0

    def consume(self, count: int = 1) -> list[QueuedAction]:
        # "0" first: our own pending messages left by a crash are re-delivered before new ones.
        for start, block in (("0", None), (">", self.block_ms)):
            resp = self.r.xreadgroup(
                self.group, self.consumer, {self.stream: start}, count=count, block=block
            )
            items = [
                item
                for _, messages in resp or []
                for mid, fields in messages
                if (item := self._parse(mid, fields)) is not None
            ]
            if items:
                return items
        return []

    def ack(self, message_id: str) -> bool:
        return bool(self.r.xack(self.stream, self.group, message_id))

    def _parse(self, mid: str, fields: dict | None) -> QueuedAction | None:
        try:
            return QueuedAction(
                message_id=mid,
                request=ActionRequest.model_validate_json((fields or {})["request"]),
            )
        except (KeyError, ValidationError) as exc:
            self.r.xadd(
                f"{self.stream}:dlq",
                {"message_id": mid, "fields": json.dumps(fields), "error": str(exc)[:500]},
            )
            self.ack(mid)
            return None


class RedisResultStore:
    """Idempotency results kept in Redis so a restarted executor never repeats an action."""

    def __init__(self, client: redis.Redis, key: str = "executor:results") -> None:
        self.r = client
        self.key = key

    def __contains__(self, idem_key: str) -> bool:
        return bool(self.r.hexists(self.key, idem_key))

    def __getitem__(self, idem_key: str) -> ActionResult:
        raw = self.r.hget(self.key, idem_key)
        if raw is None:
            raise KeyError(idem_key)
        return ActionResult.model_validate_json(raw)

    def __setitem__(self, idem_key: str, result: ActionResult) -> None:
        self.r.hset(self.key, idem_key, result.model_dump_json())


def redis_from_env() -> redis.Redis | None:
    if os.getenv("SENTINEL_ACTION_QUEUE", "memory") != "redis":
        return None
    return redis.Redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    )


def mock_producer(queue: InMemoryActionQueue | RedisActionQueue, requests: list[ActionRequest]) -> list[str]:
    """Stand-in for Habiba/Alaa producers until real streams exist."""
    return queue.enqueue_many(requests)
