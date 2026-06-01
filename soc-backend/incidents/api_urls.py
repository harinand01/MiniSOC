from django.urls import path
from . import views

urlpatterns = [
    path('', views.incident_list_create, name='incident-list-create'),
    path('open/', views.incident_open_list, name='incident-open-list'),
    path('stats/', views.incident_stats, name='incident-stats'),
    path('<int:pk>/', views.incident_detail_update_delete, name='incident-detail-update-delete'),
    path('<int:pk>/link-alert/', views.incident_link_alert, name='incident-link-alert'),
]
