"""Bus d'evenements pour la diffusion WebSocket temps reel.

Les scans tournent dans des threads de travail (I/O disque bloquantes, appels
ClamAV) tandis que les WebSockets vivent dans la boucle asyncio. Le pont se fait
uniquement via `publish_threadsafe`, qui reinjecte l'evenement dans la boucle.

Les evenements de progression sont volontairement "perissables" : si un client
lent sature sa file, on ecrase l'ancienne progression plutot que de bloquer le
scan. Les evenements de cycle de vie (menace detectee, scan termine) ne sont
jamais perdus.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

log = logging.getLogger(__name__)

# Types d'evenements. Le frontend s'appuie sur ces chaines exactes.
EVT_SCAN_STARTED = "scan.started"
EVT_SCAN_PROGRESS = "scan.progress"
EVT_SCAN_THREAT = "scan.threat"
EVT_SCAN_FINISHED = "scan.finished"
EVT_SCAN_ERROR = "scan.error"
EVT_DEVICE_CONNECTED = "device.connected"
EVT_DEVICE_DISCONNECTED = "device.disconnected"
EVT_QUARANTINE_CHANGED = "quarantine.changed"

# Evenements que l'on peut ecraser quand un client n'arrive pas a suivre.
_COALESCABLE = {EVT_SCAN_PROGRESS}

QUEUE_SIZE = 256


class Subscriber:
    """Une connexion WebSocket, avec sa file et son filtre optionnel de scan."""

    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.dropped = 0

    def wants(self, event: dict[str, Any]) -> bool:
        if self.scan_id is None:
            return True
        data = event.get("data") or {}
        return data.get("scan_id") == self.scan_id

    def offer(self, event: dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        if event["type"] in _COALESCABLE:
            # Progression : on jette la plus ancienne et on garde la plus recente.
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(event)
                self.dropped += 1
                return
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass
        self.dropped += 1
        log.warning("client WebSocket sature, evenement %s perdu", event["type"])


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[Subscriber] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Appele au demarrage de FastAPI, depuis la boucle qui servira les WS."""
        self._loop = loop

    # -- abonnements ------------------------------------------------------- #

    def subscribe(self, scan_id: str | None = None) -> Subscriber:
        sub = Subscriber(scan_id)
        self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        self._subscribers.discard(sub)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    # -- publication ------------------------------------------------------- #

    def publish(self, event_type: str, data: dict[str, Any]) -> None:
        """A appeler depuis la boucle asyncio."""
        event = {"type": event_type, "ts": time.time(), "data": data}
        for sub in list(self._subscribers):
            if sub.wants(event):
                sub.offer(event)

    def publish_threadsafe(self, event_type: str, data: dict[str, Any]) -> None:
        """A appeler depuis un thread de scan."""
        loop = self._loop
        if loop is None or loop.is_closed():
            # Mode CLI : aucune boucle, aucun client. On ignore silencieusement.
            return
        loop.call_soon_threadsafe(self.publish, event_type, data)


# Instance unique partagee par les routes et les moteurs de scan.
bus = EventBus()
