import datetime
from django.shortcuts import render
from django.db import models
from django.utils import timezone
from django.db.models.functions import ExtractHour
from rest_framework.decorators import api_view
from rest_framework.response import Response

from logs.models import Log, Alert
from incidents.models import Incident

# Helper: Parse date and days parameters
def parse_date_params(request):
    days_str = request.query_params.get('days')
    start_date_str = request.query_params.get('start_date')
    end_date_str = request.query_params.get('end_date')
    
    now = timezone.now()
    end_date = now
    
    if end_date_str:
        try:
            # Parse as local date then convert to datetime ending at 23:59:59
            dt = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
            end_date = timezone.make_aware(dt).replace(hour=23, minute=59, second=59)
        except ValueError:
            pass
            
    if days_str:
        try:
            days = int(days_str)
            # Subtract days from end_date (start at 00:00:00 of that day)
            start_dt = end_date - datetime.timedelta(days=days - 1)
            start_date = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        except ValueError:
            start_date = None
    elif start_date_str:
        try:
            dt = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
            start_date = timezone.make_aware(dt).replace(hour=0, minute=0, second=0)
        except ValueError:
            start_date = None
    else:
        # Default for "summary" is all time if no parameter is provided
        start_date = None
        
    return start_date, end_date

# Helper: Get stats for a specific range
def get_stats_for_range(start_date, end_date):
    logs_filter = Log.objects.all()
    alerts_filter = Alert.objects.all()
    incidents_filter = Incident.objects.all()
    
    if start_date:
        logs_filter = logs_filter.filter(timestamp__range=(start_date, end_date))
        alerts_filter = alerts_filter.filter(log__timestamp__range=(start_date, end_date))
        incidents_filter = incidents_filter.filter(created_at__range=(start_date, end_date))
        
    total_logs = logs_filter.count()
    total_attacks = alerts_filter.filter(verdict='ATTACK').count()
    total_suspicious = alerts_filter.filter(verdict='SUSPICIOUS').count()
    total_normal = alerts_filter.filter(verdict='NORMAL').count()
    total_incidents = incidents_filter.count()
    
    detection_rate = f"{((total_attacks + total_suspicious) / total_logs * 100):.1f}%" if total_logs > 0 else "0.0%"
    
    return {
        "total_logs": total_logs,
        "total_attacks": total_attacks,
        "total_suspicious": total_suspicious,
        "total_normal": total_normal,
        "total_incidents": total_incidents,
        "detection_rate": detection_rate
    }

# ─── API Endpoints ─────────────────────────────────────────────────────────────

@api_view(["GET"])
def daily_report(request):
    """
    GET /api/reports/daily/?date=YYYY-MM-DD
    Returns summary data for the specific date.
    """
    date_str = request.query_params.get('date')
    if date_str:
        try:
            target_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({"error": "Invalid date format. Use YYYY-MM-DD"}, status=400)
    else:
        target_date = timezone.now().date()
        
    # Start and end of the day in UTC
    start_date = timezone.make_aware(datetime.datetime.combine(target_date, datetime.time.min))
    end_date = timezone.make_aware(datetime.datetime.combine(target_date, datetime.time.max))
    
    stats = get_stats_for_range(start_date, end_date)
    
    # ── Top Attacking IPs ──────────────────────────────────────────────────────
    top_attackers_qs = Alert.objects.filter(
        verdict='ATTACK',
        log__timestamp__range=(start_date, end_date)
    ).values('log__ip_address').annotate(
        count=models.Count('id')
    ).order_by('-count')[:10]
    
    top_attacking_ips = []
    for item in top_attackers_qs:
        ip = item['log__ip_address']
        dominant = Alert.objects.filter(
            verdict='ATTACK',
            log__timestamp__range=(start_date, end_date),
            log__ip_address=ip
        ).values('attack_type').annotate(
            type_count=models.Count('id')
        ).order_by('-type_count').first()
        
        top_attacking_ips.append({
            "ip": ip,
            "count": item['count'],
            "attack_type": dominant['attack_type'] if dominant else 'none'
        })
        
    # ── Attack Type Breakdown ──────────────────────────────────────────────────
    attack_types_qs = Alert.objects.filter(
        verdict='ATTACK',
        log__timestamp__range=(start_date, end_date)
    ).values('attack_type').annotate(
        count=models.Count('id')
    ).order_by('-count')
    
    total_attacks = stats["total_attacks"]
    attack_type_breakdown = []
    for item in attack_types_qs:
        pct = (item['count'] / total_attacks * 100) if total_attacks > 0 else 0.0
        attack_type_breakdown.append({
            "type": item['attack_type'],
            "count": item['count'],
            "percentage": round(pct, 1)
        })
        
    # ── Hourly Trend ───────────────────────────────────────────────────────────
    logs_by_hour = Log.objects.filter(
        timestamp__range=(start_date, end_date)
    ).annotate(
        hour=ExtractHour('timestamp')
    ).values('hour').annotate(
        count=models.Count('id')
    )
    
    attacks_by_hour = Alert.objects.filter(
        verdict='ATTACK',
        log__timestamp__range=(start_date, end_date)
    ).annotate(
        hour=ExtractHour('log__timestamp')
    ).values('hour').annotate(
        count=models.Count('id')
    )
    
    logs_map = {item['hour']: item['count'] for item in logs_by_hour if item['hour'] is not None}
    attacks_map = {item['hour']: item['count'] for item in attacks_by_hour if item['hour'] is not None}
    
    hourly_trend = []
    for h in range(24):
        hourly_trend.append({
            "hour": h,
            "attacks": attacks_map.get(h, 0),
            "total": logs_map.get(h, 0)
        })
        
    return Response({
        "date": target_date.strftime('%Y-%m-%d'),
        "total_logs": stats["total_logs"],
        "total_attacks": stats["total_attacks"],
        "total_suspicious": stats["total_suspicious"],
        "total_normal": stats["total_normal"],
        "total_incidents": stats["total_incidents"],
        "detection_rate": stats["detection_rate"],
        "top_attacking_ips": top_attacking_ips,
        "attack_type_breakdown": attack_type_breakdown,
        "hourly_trend": hourly_trend
    })


@api_view(["GET"])
def weekly_report(request):
    """
    GET /api/reports/weekly/
    Returns summary data and a daily breakdown for the last 7 days.
    """
    end_date = timezone.now()
    start_date = (end_date - datetime.timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Last 7 Days overall stats
    summary = get_stats_for_range(start_date, end_date)
    
    # ── Top Attacking IPs ──────────────────────────────────────────────────────
    top_attackers_qs = Alert.objects.filter(
        verdict='ATTACK',
        log__timestamp__range=(start_date, end_date)
    ).values('log__ip_address').annotate(
        count=models.Count('id')
    ).order_by('-count')[:10]
    
    top_attacking_ips = []
    for item in top_attackers_qs:
        ip = item['log__ip_address']
        dominant = Alert.objects.filter(
            verdict='ATTACK',
            log__timestamp__range=(start_date, end_date),
            log__ip_address=ip
        ).values('attack_type').annotate(
            type_count=models.Count('id')
        ).order_by('-type_count').first()
        
        top_attacking_ips.append({
            "ip": ip,
            "count": item['count'],
            "attack_type": dominant['attack_type'] if dominant else 'none'
        })
        
    summary["top_attacking_ips"] = top_attacking_ips
    
    # ── Attack Type Breakdown ──────────────────────────────────────────────────
    attack_types_qs = Alert.objects.filter(
        verdict='ATTACK',
        log__timestamp__range=(start_date, end_date)
    ).values('attack_type').annotate(
        count=models.Count('id')
    ).order_by('-count')
    
    total_attacks = summary["total_attacks"]
    attack_type_breakdown = []
    for item in attack_types_qs:
        pct = (item['count'] / total_attacks * 100) if total_attacks > 0 else 0.0
        attack_type_breakdown.append({
            "type": item['attack_type'],
            "count": item['count'],
            "percentage": round(pct, 1)
        })
        
    summary["attack_type_breakdown"] = attack_type_breakdown
    
    # ── Daily Breakdown list ───────────────────────────────────────────────────
    daily_breakdown = []
    for i in range(7):
        day_date = (start_date + datetime.timedelta(days=i)).date()
        day_start = timezone.make_aware(datetime.datetime.combine(day_date, datetime.time.min))
        day_end = timezone.make_aware(datetime.datetime.combine(day_date, datetime.time.max))
        
        day_stats = get_stats_for_range(day_start, day_end)
        daily_breakdown.append({
            "date": day_date.strftime('%Y-%m-%d'),
            "total_logs": day_stats["total_logs"],
            "total_attacks": day_stats["total_attacks"],
            "total_suspicious": day_stats["total_suspicious"],
            "total_normal": day_stats["total_normal"],
            "total_incidents": day_stats["total_incidents"],
            "detection_rate": day_stats["detection_rate"]
        })
        
    return Response({
        "summary": summary,
        "daily_breakdown": daily_breakdown
    })


@api_view(["GET"])
def top_ips(request):
    """
    GET /api/reports/top-ips/?limit=10&days=7
    Returns the top attacking IPs for all time (or filtered by range) with full stats.
    """
    limit = int(request.query_params.get("limit", 10))
    start_date, end_date = parse_date_params(request)
    
    alerts_qs = Alert.objects.filter(verdict='ATTACK')
    if start_date:
        alerts_qs = alerts_qs.filter(log__timestamp__range=(start_date, end_date))
        
    top_ips_qs = alerts_qs.values('log__ip_address').annotate(
        count=models.Count('id'),
        first_seen=models.Min('log__timestamp'),
        last_seen=models.Max('log__timestamp')
    ).order_by('-count')[:limit]
    
    results = []
    for item in top_ips_qs:
        ip = item['log__ip_address']
        dominant_qs = Alert.objects.filter(verdict='ATTACK', log__ip_address=ip)
        if start_date:
            dominant_qs = dominant_qs.filter(log__timestamp__range=(start_date, end_date))
            
        dominant = dominant_qs.values('attack_type').annotate(
            type_count=models.Count('id')
        ).order_by('-type_count').first()
        
        results.append({
            "ip_address": ip,
            "total_attacks": item['count'],
            "attack_type": dominant['attack_type'] if dominant else 'none',
            "first_seen": item['first_seen'].isoformat() if item['first_seen'] else None,
            "last_seen": item['last_seen'].isoformat() if item['last_seen'] else None,
        })
        
    return Response(results)


@api_view(["GET"])
def attack_types(request):
    """
    GET /api/reports/attack-types/?days=7
    Returns counts and percentages for all attack types.
    """
    start_date, end_date = parse_date_params(request)
    
    alerts_qs = Alert.objects.filter(verdict='ATTACK')
    if start_date:
        alerts_qs = alerts_qs.filter(log__timestamp__range=(start_date, end_date))
        
    total_attacks = alerts_qs.count()
    types_qs = alerts_qs.values('attack_type').annotate(
        count=models.Count('id')
    ).order_by('-count')
    
    results = []
    for item in types_qs:
        pct = (item['count'] / total_attacks * 100) if total_attacks > 0 else 0.0
        results.append({
            "type": item['attack_type'],
            "count": item['count'],
            "percentage": round(pct, 1)
        })
        
    return Response(results)


@api_view(["GET"])
def summary(request):
    """
    GET /api/reports/summary/?days=7
    Returns overall system summary totals and breakdown trends for a time range.
    """
    start_date, end_date = parse_date_params(request)
    
    stats = get_stats_for_range(start_date, end_date)
    
    # ── Attack Type Breakdown ──────────────────────────────────────────────────
    alerts_qs = Alert.objects.filter(verdict='ATTACK')
    if start_date:
        alerts_qs = alerts_qs.filter(log__timestamp__range=(start_date, end_date))
        
    attack_types_qs = alerts_qs.values('attack_type').annotate(
        count=models.Count('id')
    ).order_by('-count')
    
    total_attacks = stats["total_attacks"]
    attack_type_breakdown = []
    for item in attack_types_qs:
        pct = (item['count'] / total_attacks * 100) if total_attacks > 0 else 0.0
        attack_type_breakdown.append({
            "type": item['attack_type'],
            "count": item['count'],
            "percentage": round(pct, 1)
        })
        
    # ── Hourly Trend ───────────────────────────────────────────────────────────
    logs_qs = Log.objects.all()
    if start_date:
        logs_qs = logs_qs.filter(timestamp__range=(start_date, end_date))
        
    logs_by_hour = logs_qs.annotate(
        hour=ExtractHour('timestamp')
    ).values('hour').annotate(
        count=models.Count('id')
    )
    
    attacks_by_hour = alerts_qs.annotate(
        hour=ExtractHour('log__timestamp')
    ).values('hour').annotate(
        count=models.Count('id')
    )
    
    logs_map = {item['hour']: item['count'] for item in logs_by_hour if item['hour'] is not None}
    attacks_map = {item['hour']: item['count'] for item in attacks_by_hour if item['hour'] is not None}
    
    hourly_trend = []
    for h in range(24):
        hourly_trend.append({
            "hour": h,
            "attacks": attacks_map.get(h, 0),
            "total": logs_map.get(h, 0)
        })
        
    # ── Top 10 Attacking IPs ───────────────────────────────────────────────────
    top_attackers_qs = alerts_qs.values('log__ip_address').annotate(
        count=models.Count('id'),
        first_seen=models.Min('log__timestamp'),
        last_seen=models.Max('log__timestamp')
    ).order_by('-count')[:10]
    
    top_attacking_ips = []
    for item in top_attackers_qs:
        ip = item['log__ip_address']
        dominant_qs = Alert.objects.filter(verdict='ATTACK', log__ip_address=ip)
        if start_date:
            dominant_qs = dominant_qs.filter(log__timestamp__range=(start_date, end_date))
        dominant = dominant_qs.values('attack_type').annotate(
            type_count=models.Count('id')
        ).order_by('-type_count').first()
        
        top_attacking_ips.append({
            "ip_address": ip,
            "total_attacks": item['count'],
            "attack_type": dominant['attack_type'] if dominant else 'none',
            "first_seen": item['first_seen'].isoformat() if item['first_seen'] else None,
            "last_seen": item['last_seen'].isoformat() if item['last_seen'] else None,
        })
        
    return Response({
        "total_logs": stats["total_logs"],
        "total_attacks": stats["total_attacks"],
        "total_suspicious": stats["total_suspicious"],
        "total_normal": stats["total_normal"],
        "total_incidents": stats["total_incidents"],
        "detection_rate": stats["detection_rate"],
        "attack_type_breakdown": attack_type_breakdown,
        "hourly_trend": hourly_trend,
        "top_attacking_ips": top_attacking_ips
    })


# ─── Template Render Views ─────────────────────────────────────────────────────

def index(request):
    """
    Renders the /reports/ page.
    """
    return render(request, "reports/index.html")
