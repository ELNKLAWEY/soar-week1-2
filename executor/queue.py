"""In-memory action queue (Week 1–2 stand-in for Redis Streams).

Week 3+: replace with Redis Streams XADD / XREADGROUP / XACK on stream `actions`.
Set SENTINEL_ACTION_QUEUE=redis when Alaa's streams are ready.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterator
from uuid import uuid4

from common.schemas.actions import ActionRequest


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

    def drain(self) -> Iterator[QueuedAction]:
        while self._items:
            batch = self.consume(1)
            if not batch:
                break
            yield batch[0]


def mock_producer(queue: InMemoryActionQueue, requests: list[ActionRequest]) -> list[str]:
    """Stand-in for Habiba/Alaa producers until real streams exist."""
    return queue.enqueue_many(requests)
