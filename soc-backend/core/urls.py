from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('logs.urls')),
    path('api/incidents/', include('incidents.api_urls')),
    path('api/reports/', include('reports.api_urls')),
    path('dashboard/', include('dashboard.urls')),
    path('incidents/', include('incidents.urls')),
    path('reports/', include('reports.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
