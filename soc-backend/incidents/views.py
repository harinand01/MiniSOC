from django.shortcuts import render
from django.db.models import Count
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from logs.views import StandardPagination
from logs.models import Alert
from .models import Incident
from .serializers import IncidentSerializer

# ─── API Endpoints ─────────────────────────────────────────────────────────────

@api_view(["GET", "POST"])
def incident_list_create(request):
    """
    GET  /api/incidents/  - list all incidents newest first
    POST /api/incidents/  - create new incident manually
    """
    if request.method == "GET":
        qs = Incident.objects.prefetch_related("alerts", "alerts__log").order_by("-created_at")
        paginator = StandardPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = IncidentSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
        
    elif request.method == "POST":
        serializer = IncidentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PATCH", "DELETE"])
def incident_detail_update_delete(request, pk):
    """
    GET    /api/incidents/{id}/  - full detail with linked alerts
    PATCH  /api/incidents/{id}/  - update status, notes, assigned_to
    DELETE /api/incidents/{id}/  - delete incident
    """
    try:
        incident = Incident.objects.prefetch_related("alerts", "alerts__log").get(pk=pk)
    except Incident.DoesNotExist:
        return Response({"error": "Incident not found."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = IncidentSerializer(incident)
        return Response(serializer.data)

    elif request.method == "PATCH":
        serializer = IncidentSerializer(incident, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == "DELETE":
        incident.delete()
        return Response({"message": "Incident deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


@api_view(["POST"])
def incident_link_alert(request, pk):
    """
    POST /api/incidents/{id}/link-alert/  - link an existing alert to incident
    Body:
        { "alert_id": 123 }
    """
    try:
        incident = Incident.objects.get(pk=pk)
    except Incident.DoesNotExist:
        return Response({"error": "Incident not found."}, status=status.HTTP_404_NOT_FOUND)

    alert_id = request.data.get("alert_id")
    if not alert_id:
        return Response({"error": "alert_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        alert = Alert.objects.get(pk=alert_id)
    except Alert.DoesNotExist:
        return Response({"error": "Alert not found."}, status=status.HTTP_404_NOT_FOUND)

    incident.alerts.add(alert)
    return Response(IncidentSerializer(incident).data)


@api_view(["GET"])
def incident_open_list(request):
    """
    GET /api/incidents/open/  - only open incidents
    """
    qs = Incident.objects.filter(status="open").prefetch_related("alerts", "alerts__log").order_by("-created_at")
    paginator = StandardPagination()
    page = paginator.paginate_queryset(qs, request)
    serializer = IncidentSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(["GET"])
def incident_stats(request):
    """
    GET /api/incidents/stats/  - count by status and severity
    """
    status_counts = Incident.objects.values("status").annotate(count=Count("id"))
    severity_counts = Incident.objects.values("severity").annotate(count=Count("id"))
    
    status_dict = {item["status"]: item["count"] for item in status_counts}
    severity_dict = {item["severity"]: item["count"] for item in severity_counts}
    
    # Defaults
    for s in ["open", "in_progress", "closed"]:
        status_dict.setdefault(s, 0)
    for sev in ["critical", "high", "medium", "low"]:
        severity_dict.setdefault(sev, 0)

    return Response({
        "by_status": status_dict,
        "by_severity": severity_dict,
        "total": Incident.objects.count()
    })


# ─── Template Views ────────────────────────────────────────────────────────────

def incidents_dashboard(request):
    """
    Renders the /incidents/ HTML page.
    """
    return render(request, "incidents/index.html")
