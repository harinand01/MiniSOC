"""
WebSocket consumer for real-time SOC alert streaming.

Every connected browser tab joins the "soc_alerts" group.
The Kafka consumer calls channel_layer.group_send() which
triggers send_alert() on every connected client instantly.
"""

import json
from channels.generic.websocket import AsyncWebsocketConsumer


class AlertConsumer(AsyncWebsocketConsumer):
    GROUP_NAME = "soc_alerts"

    async def connect(self):
        """Browser opened a WebSocket connection."""
        await self.channel_layer.group_add(self.GROUP_NAME, self.channel_name)
        await self.accept()
        # Confirm connection to the client
        await self.send(text_data=json.dumps({
            "type": "connection_established",
            "message": "SOC WebSocket connected. Listening for live alerts...",
        }))

    async def disconnect(self, close_code):
        """Browser closed the tab / connection dropped."""
        await self.channel_layer.group_discard(self.GROUP_NAME, self.channel_name)

    async def receive(self, text_data):
        """
        Messages FROM the browser (ping / keep-alive).
        Browsers don't normally send data here — just echo back.
        """
        try:
            data = json.loads(text_data)
            await self.send(text_data=json.dumps({"type": "pong", "received": data}))
        except Exception:
            pass

    # ── Called by channel layer when Kafka consumer pushes an event ────────────
    async def send_alert(self, event):
        """
        Called when the Kafka consumer does:
            channel_layer.group_send("soc_alerts", {"type": "send_alert", "data": {...}})

        Forwards the payload to every connected browser.
        """
        await self.send(text_data=json.dumps(event["data"]))
