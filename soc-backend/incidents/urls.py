from django.urls import path
from . import views

urlpatterns = [
    path('', views.incidents_dashboard, name='incidents_dashboard'),
]
