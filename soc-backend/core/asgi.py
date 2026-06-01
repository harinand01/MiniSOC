"""
ASGI config — handles both HTTP (Django) and WebSocket (Channels) traffic.
"""

import os
import django
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from core.routing import websocket_urlpatterns  # import AFTER django.setup()

from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler

application = ProtocolTypeRouter({
    # Standard HTTP requests → regular Django views
    "http": ASGIStaticFilesHandler(get_asgi_application()),

    # WebSocket requests → Channels consumer
    "websocket": AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})
