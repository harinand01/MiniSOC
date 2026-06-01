from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('alerts/', views.alerts, name='alerts'),
    path('logs/', views.logs, name='logs'),
    path('ip/<str:ip>/', views.ip_investigation, name='ip_investigation'),
]
