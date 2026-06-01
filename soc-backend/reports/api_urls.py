from django.urls import path
from . import views

urlpatterns = [
    path('daily/', views.daily_report, name='api_reports_daily'),
    path('weekly/', views.weekly_report, name='api_reports_weekly'),
    path('top-ips/', views.top_ips, name='api_reports_top_ips'),
    path('attack-types/', views.attack_types, name='api_reports_attack_types'),
    path('summary/', views.summary, name='api_reports_summary'),
]
