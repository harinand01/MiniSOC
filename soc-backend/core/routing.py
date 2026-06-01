"""
WebSocket URL routing.
Maps ws://host/ws/alerts/ → AlertConsumer
"""

from django.urls import re_path
from logs.consumers import AlertConsumer

websocket_urlpatterns = [
    re_path(r"^ws/alerts/$", AlertConsumer.as_asgi()),
]
