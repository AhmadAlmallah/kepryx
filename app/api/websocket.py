"""WebSocket real-time event stream.

UI client -> authenticated REST ticket -> WS /ws/events?ticket=<opaque one-time ticket>
Celery workers -> Redis pubsub channel kepryx:events
"""

import asyncio
import json
import logging
import secrets

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from redis.asyncio import Redis
from sqlalchemy import select

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import SessionLocal
from app.models import User

logger = logging.getLogger(__name__)
router = APIRouter()

TOPICS = {
    "alerts": ("viewer", "analyst", "admin"),
    "assets": ("viewer", "analyst", "admin"),
    "scans": ("analyst", "admin"),
    "self_security": ("admin",),
    "audit": ("admin",),
    "system": ("viewer", "analyst", "admin"),
}


class WSClient:
    __slots__ = ("ws", "user_id", "username", "role", "topics")

    def __init__(self, ws, user_id, username, role):
        self.ws = ws
        self.user_id = user_id
        self.username = username
        self.role = role
        self.topics = set()

    def can_subscribe(self, topic):
        return self.role in TOPICS.get(topic, ())


class ConnectionManager:
    def __init__(self):
        self.clients = set()
        self._lock = asyncio.Lock()
        self._redis = None
        self._pubsub_task = None
        self._started = False

    async def start(self):
        if self._started:
            return
        self._started = True
        try:
            self._redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
            self._pubsub_task = asyncio.create_task(self._redis_listener())
            logger.info("WS ConnectionManager started")
        except Exception as e:
            logger.error("WS manager failed to start: %s", e)
            self._started = False

    async def stop(self):
        if self._pubsub_task:
            self._pubsub_task.cancel()
            try:
                await self._pubsub_task
            except asyncio.CancelledError:
                logger.debug("WebSocket pubsub task cancelled")
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                logger.debug("WebSocket Redis close failed", exc_info=True)

    async def connect(self, client):
        await client.ws.accept()
        async with self._lock:
            self.clients.add(client)
        await self._send(
            client,
            {
                "type": "connected",
                "user": client.username,
                "role": client.role,
                "available_topics": [t for t in TOPICS if client.can_subscribe(t)],
            },
        )
        logger.info(
            "WS connect: %s (%s); total=%d", client.username, client.role, len(self.clients)
        )

    async def disconnect(self, client):
        async with self._lock:
            self.clients.discard(client)

    async def _send(self, client, payload):
        try:
            await client.ws.send_text(json.dumps(payload))
        except Exception as e:
            logger.warning("WS send failed: %s", e)

    async def broadcast(self, topic, payload):
        msg = {"topic": topic, "data": payload}
        async with self._lock:
            targets = [c for c in self.clients if topic in c.topics and c.can_subscribe(topic)]
        for client in targets:
            await self._send(client, msg)

    async def _redis_listener(self):
        try:
            pubsub = self._redis.pubsub()
            await pubsub.subscribe("kepryx:events")
            async for msg in pubsub.listen():
                if msg["type"] != "message":
                    continue
                try:
                    event = json.loads(msg["data"])
                    await self.broadcast(event.get("topic", "system"), event.get("data", {}))
                except Exception as e:
                    logger.warning("Pubsub handler: %s", e)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception("Redis listener crashed: %s", e)


manager = ConnectionManager()


@router.post(f"{settings.API_V1_PREFIX}/ws/ticket")
async def issue_websocket_ticket(user: User = Depends(get_current_user)):
    await manager.start()
    if manager._redis is None:
        raise RuntimeError("WebSocket ticket service unavailable")
    ticket = secrets.token_urlsafe(32)
    await manager._redis.setex(f"ws:ticket:{ticket}", 30, str(user.id))
    return {"ticket": ticket, "expires_in": 30}


async def authenticate_ws(ticket):
    if not ticket or manager._redis is None:
        return None
    try:
        user_id = await manager._redis.getdel(f"ws:ticket:{ticket}")
        if not user_id:
            return None
        async with SessionLocal() as db:
            user = await db.scalar(select(User).where(User.id == user_id))
            if not user or not user.is_active:
                return None
            return str(user.id), user.username, user.role
    except Exception:
        logger.exception("WebSocket ticket validation failed")
        return None


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, ticket: str = Query(...)):
    await manager.start()
    origin = websocket.headers.get("origin")
    if settings.ENVIRONMENT == "production" and origin not in settings.CORS_ORIGINS:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    auth = await authenticate_ws(ticket)
    if not auth:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id, username, role = auth
    client = WSClient(websocket, user_id, username, role)
    await manager.connect(client)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            action = msg.get("action")
            if action == "subscribe":
                for t in msg.get("topics", []):
                    if client.can_subscribe(t):
                        client.topics.add(t)
                await manager._send(client, {"type": "subscribed", "topics": list(client.topics)})
            elif action == "unsubscribe":
                for t in msg.get("topics", []):
                    client.topics.discard(t)
                await manager._send(client, {"type": "unsubscribed", "topics": list(client.topics)})
            elif action == "ping":
                await manager._send(client, {"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("WS loop error: %s", e)
    finally:
        await manager.disconnect(client)


async def publish_event(topic, data):
    try:
        if manager._redis is None:
            await manager.start()
        if manager._redis is not None:
            await manager._redis.publish(
                "kepryx:events", json.dumps({"topic": topic, "data": data})
            )
    except Exception as e:
        logger.debug("WS publish: %s", e)


def publish_event_sync(topic, data):
    import redis as sync_redis

    try:
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        r.publish("kepryx:events", json.dumps({"topic": topic, "data": data}))
        r.close()
    except Exception as e:
        logger.debug("WS sync publish: %s", e)
