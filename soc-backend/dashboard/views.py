from django.shortcuts import render
from django.contrib.auth.decorators import login_required

def index(request):
    return render(request, 'dashboard/index.html')

def alerts(request):
    return render(request, 'dashboard/alerts.html')

def logs(request):
    return render(request, 'dashboard/logs.html')

def ip_investigation(request, ip):
    return render(request, 'dashboard/ip_investigation.html', {'ip': ip})
