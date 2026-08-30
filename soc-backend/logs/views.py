"""
API Views for the SOC Platform.

Endpoints:
    GET  /api/logs/                  - list all logs (paginated, newest first)
    GET  /api/logs/?verdict=ATTACK   - filter logs by alert verdict
    GET  /api/alerts/                - list all alerts
    GET  /api/alerts/unreviewed/     - only unreviewed alerts
    PATCH /api/alerts/{id}/          - mark alert reviewed / update fields
    GET  /api/stats/                 - summary counts and top attackers
"""

import datetime
from collections import Counter

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from .models import Alert, Log, BlockedIP, InvestigationNote
from .serializers import AlertSerializer, LogSerializer, BlockedIPSerializer, InvestigationNoteSerializer



# ─── Pagination ────────────────────────────────────────────────────────────────

class StandardPagination(PageNumberPagination):
    page_size            = 50
    page_size_query_param = "page_size"
    max_page_size        = 500


# ─── Log Endpoints ─────────────────────────────────────────────────────────────

@api_view(["GET"])
def log_list(request):
    """
    GET /api/logs/
    Optional query params:
        ?verdict=ATTACK|SUSPICIOUS|NORMAL
        ?ip=<ip_address>
        ?event_type=login_failure|login_success|api_access
        ?page=1&page_size=50
    """
    qs = Log.objects.order_by("-timestamp")

    # Filter by alert verdict (join through alert table)
    verdict = request.query_params.get("verdict")
    if verdict:
        qs = qs.filter(alert__verdict=verdict.upper())

    # Filter by IP
    ip = request.query_params.get("ip")
    if ip:
        qs = qs.filter(ip_address=ip)

    # Filter by event type
    event_type = request.query_params.get("event_type")
    if event_type:
        qs = qs.filter(event_type=event_type)

    paginator  = StandardPagination()
    page       = paginator.paginate_queryset(qs, request)
    serializer = LogSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)


# ─── Alert Endpoints ────────────────────────────────────────────────────────────

@api_view(["GET"])
def alert_list(request):
    """
    GET /api/alerts/
    Optional query params:
        ?verdict=ATTACK|SUSPICIOUS|NORMAL
        ?attack_type=brute_force|suspicious_login|blacklisted_ip|none
        ?is_reviewed=true|false
        ?page=1&page_size=50
    """
    qs = Alert.objects.select_related("log").order_by("-created_at")

    verdict = request.query_params.get("verdict")
    if verdict:
        qs = qs.filter(verdict=verdict.upper())

    ip = request.query_params.get("ip")
    if ip:
        qs = qs.filter(log__ip_address=ip)

    attack_type = request.query_params.get("attack_type")

    if attack_type:
        qs = qs.filter(attack_type=attack_type)

    is_reviewed = request.query_params.get("is_reviewed")
    if is_reviewed is not None:
        qs = qs.filter(is_reviewed=(is_reviewed.lower() == "true"))

    paginator  = StandardPagination()
    page       = paginator.paginate_queryset(qs, request)
    serializer = AlertSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(["GET"])
def alert_unreviewed(request):
    """
    GET /api/alerts/unreviewed/
    Returns all alerts that haven't been reviewed yet, newest first.
    """
    qs = (
        Alert.objects
        .select_related("log")
        .filter(is_reviewed=False)
        .order_by("-created_at")
    )
    paginator  = StandardPagination()
    page       = paginator.paginate_queryset(qs, request)
    serializer = AlertSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(["PATCH"])
def alert_detail(request, pk):
    """
    PATCH /api/alerts/{id}/
    Supports partial updates. Common use: mark as reviewed.

    Body (JSON):
        { "is_reviewed": true }
    """
    try:
        alert = Alert.objects.select_related("log").get(pk=pk)
    except Alert.DoesNotExist:
        return Response({"error": "Alert not found."}, status=status.HTTP_404_NOT_FOUND)

    serializer = AlertSerializer(alert, data=request.data, partial=True)
    if serializer.is_valid():
        instance = serializer.save()
        if request.data.get("is_reviewed") is True:
            instance.status = "resolved"
            instance.save()
        return Response(AlertSerializer(instance).data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ─── Stats Endpoint ─────────────────────────────────────────────────────────────

@api_view(["GET"])
def stats(request):
    """
    GET /api/stats/
    Returns a summary of key SOC metrics.
    """
    now   = timezone.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # ── Totals ─────────────────────────────────────────────────────────────────
    total_logs   = Log.objects.count()
    total_alerts = Alert.objects.count()

    # ── Today's counts ─────────────────────────────────────────────────────────
    attacks_today    = Alert.objects.filter(
        verdict="ATTACK", created_at__gte=today
    ).count()
    suspicious_today = Alert.objects.filter(
        verdict="SUSPICIOUS", created_at__gte=today
    ).count()
    normal_today     = Alert.objects.filter(
        verdict="NORMAL", created_at__gte=today
    ).count()

    # ── Unreviewed ─────────────────────────────────────────────────────────────
    unreviewed_count = Alert.objects.filter(is_reviewed=False).count()

    # ── Verdict distribution (all time) ────────────────────────────────────────
    verdict_dist = (
        Alert.objects
        .values("verdict")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    # ── Attack type distribution ────────────────────────────────────────────────
    attack_type_dist = (
        Alert.objects
        .exclude(attack_type="none")
        .values("attack_type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    # ── Top attacking IPs (IPs with most ATTACK verdicts) ──────────────────────
    top_attackers = (
        Alert.objects
        .filter(verdict="ATTACK")
        .values("log__ip_address")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    top_attackers_list = [
        {"ip": row["log__ip_address"], "attack_count": row["count"]}
        for row in top_attackers
    ]

    # ── Logs per hour (last 24 hours) — useful for timeline chart ──────────────
    from django.db import connection
    last_24h     = now - datetime.timedelta(hours=24)
    if connection.vendor == 'sqlite':
        hourly_logs  = (
            Log.objects
            .filter(timestamp__gte=last_24h)
            .extra(select={"hour": "strftime('%%H', timestamp)"})
            .values("hour")
            .annotate(count=Count("id"))
            .order_by("hour")
        )
    else:
        hourly_logs  = (
            Log.objects
            .filter(timestamp__gte=last_24h)
            .extra(select={"hour": "date_part('hour', timestamp)"})
            .values("hour")
            .annotate(count=Count("id"))
            .order_by("hour")
        )

    return Response({
        "totals": {
            "logs":   total_logs,
            "alerts": total_alerts,
        },
        "today": {
            "attacks":    attacks_today,
            "suspicious": suspicious_today,
            "normal":     normal_today,
        },
        "unreviewed": unreviewed_count,
        "verdict_distribution":      list(verdict_dist),
        "attack_type_distribution":  list(attack_type_dist),
        "top_attackers":             top_attackers_list,
        "hourly_logs_last_24h":      list(hourly_logs),
    })


# ─── Blocked IP Endpoints ──────────────────────────────────────────────────────

@api_view(["GET", "POST"])
def blocked_ip_list_create(request):
    """
    GET  /api/blocked-ips/        - list all blocked IPs
    POST /api/blocked-ips/        - block an IP address
    """
    if request.method == "GET":
        qs = BlockedIP.objects.order_by("-blocked_at")
        serializer = BlockedIPSerializer(qs, many=True)
        return Response(serializer.data)
        
    elif request.method == "POST":
        serializer = BlockedIPSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["DELETE"])
def blocked_ip_delete(request, ip_address):
    """
    DELETE /api/blocked-ips/{ip_address}/ - unblock an IP address
    """
    try:
        blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
        blocked_ip.delete()
        return Response({"message": "IP unblocked successfully."}, status=status.HTTP_204_NO_CONTENT)
    except BlockedIP.DoesNotExist:
        return Response({"error": "Blocked IP not found."}, status=status.HTTP_404_NOT_FOUND)


@api_view(["GET", "POST"])
def ip_notes(request):
    """
    GET  /api/logs/notes/?ip=<ip>  - get notes for an IP address
    POST /api/logs/notes/          - save/update notes for an IP address
    """
    if request.method == "GET":
        ip = request.query_params.get("ip")
        if not ip:
            return Response({"error": "IP address is required."}, status=status.HTTP_400_BAD_REQUEST)
        note, created = InvestigationNote.objects.get_or_create(ip_address=ip, defaults={"notes": ""})
        serializer = InvestigationNoteSerializer(note)
        return Response(serializer.data)

    elif request.method == "POST":
        ip = request.data.get("ip_address")
        notes = request.data.get("notes", "")
        if not ip:
            return Response({"error": "ip_address is required."}, status=status.HTTP_400_BAD_REQUEST)
        note, created = InvestigationNote.objects.get_or_create(ip_address=ip)
        note.notes = notes
        note.save()
        serializer = InvestigationNoteSerializer(note)
        return Response(serializer.data, status=status.HTTP_200_OK)

