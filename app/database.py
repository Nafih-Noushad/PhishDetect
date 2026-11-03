import os
from datetime import datetime, timedelta
from sqlalchemy import func, desc, or_
from app import db
from app.models import ScanResult, ScanFinding, AppSettings


def init_db(app=None):
    """
    Initialize database tables and create default settings if they do not exist.
    """
    db.create_all()

    default_settings = [
        {
            'key': 'ollama_url',
            'value': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
            'description': 'Base URL for local or remote Ollama API endpoint'
        },
        {
            'key': 'ollama_model',
            'value': os.getenv('OLLAMA_MODEL', 'llama3.2'),
            'description': 'Default LLM model name used for phishing analysis'
        },
        {
            'key': 'app_version',
            'value': '1.0.0',
            'description': 'Current PhishDetect AI application version'
        }
    ]

    for item in default_settings:
        existing = db.session.get(AppSettings, item['key'])
        if not existing:
            setting = AppSettings(
                key=item['key'],
                value=item['value'],
                description=item['description']
            )
            db.session.add(setting)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def get_scan_by_id(scan_id):
    """
    Retrieve a ScanResult by primary key ID.
    """
    if scan_id is None:
        return None
    return db.session.get(ScanResult, scan_id)


def get_all_scans(page=1, per_page=10, search=None, category=None, sort_by='scan_timestamp', sort_dir='desc'):
    """
    Paginated query with search and category filtering and dynamic sorting.
    """
    page = max(1, int(page or 1))
    per_page = max(1, min(int(per_page or 10), 100))

    query = ScanResult.query

    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ScanResult.sender.ilike(search_term),
                ScanResult.subject.ilike(search_term)
            )
        )

    if category:
        category_clean = category.strip().upper()
        if category_clean in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
            query = query.filter(ScanResult.risk_category == category_clean)

    sort_column_map = {
        'scan_timestamp': ScanResult.scan_timestamp,
        'risk_score': ScanResult.risk_score,
        'sender': ScanResult.sender,
        'subject': ScanResult.subject,
        'risk_category': ScanResult.risk_category,
        'ai_verdict': ScanResult.ai_verdict
    }

    col = sort_column_map.get(sort_by, ScanResult.scan_timestamp)
    if str(sort_dir).lower() == 'asc':
        query = query.order_by(col.asc())
    else:
        query = query.order_by(col.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return {
        'scans': [scan.to_dict() for scan in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages
    }


def delete_scan(scan_id):
    """
    Delete a scan and its associated findings by scan_id.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        return False

    db.session.delete(scan)
    db.session.commit()
    return True


def clear_all_scans():
    """
    Delete all scans and findings from the database.
    Returns the count of deleted scans.
    """
    count = ScanResult.query.count()
    ScanFinding.query.delete()
    ScanResult.query.delete()
    db.session.commit()
    return count


def get_stats():
    """
    Return summary statistics of scanned emails.
    """
    total_scans = ScanResult.query.count()
    phishing_count = ScanResult.query.filter(
        or_(
            ScanResult.risk_category.in_(['HIGH', 'CRITICAL']),
            ScanResult.ai_verdict == 'PHISHING'
        )
    ).count()
    safe_count = ScanResult.query.filter(
        ScanResult.risk_category == 'LOW',
        ScanResult.ai_verdict != 'PHISHING'
    ).count()
    suspicious_count = ScanResult.query.filter(
        ScanResult.risk_category == 'MEDIUM'
    ).count()
    critical_count = ScanResult.query.filter(
        ScanResult.risk_category == 'CRITICAL'
    ).count()

    recent_scans = [
        scan.to_dict()
        for scan in ScanResult.query.order_by(ScanResult.scan_timestamp.desc()).limit(10).all()
    ]

    return {
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'suspicious_count': suspicious_count,
        'critical_count': critical_count,
        'recent_scans': recent_scans
    }


def get_analytics_data():
    """
    Return aggregated data for dashboard charts:
    - Daily counts for last 30 days
    - Category distribution
    - Top indicators
    - Weekly trends (last 8 weeks)
    """
    now = datetime.utcnow()
    thirty_days_ago = now - timedelta(days=29)
    start_date = datetime(thirty_days_ago.year, thirty_days_ago.month, thirty_days_ago.day)

    # 1. Daily counts for the last 30 days
    recent_records = ScanResult.query.filter(ScanResult.scan_timestamp >= start_date).all()

    daily_dict = {}
    for i in range(30):
        current_day = (start_date + timedelta(days=i)).strftime('%Y-%m-%d')
        daily_dict[current_day] = {
            'date': current_day,
            'total': 0,
            'phishing': 0,
            'safe': 0,
            'suspicious': 0
        }

    for record in recent_records:
        day_str = record.scan_timestamp.strftime('%Y-%m-%d')
        if day_str in daily_dict:
            daily_dict[day_str]['total'] += 1
            if record.risk_category in ['HIGH', 'CRITICAL'] or record.ai_verdict == 'PHISHING':
                daily_dict[day_str]['phishing'] += 1
            elif record.risk_category == 'LOW':
                daily_dict[day_str]['safe'] += 1
            elif record.risk_category == 'MEDIUM':
                daily_dict[day_str]['suspicious'] += 1

    daily_counts = list(daily_dict.values())

    # 2. Category distribution
    category_counts = {
        'LOW': ScanResult.query.filter_by(risk_category='LOW').count(),
        'MEDIUM': ScanResult.query.filter_by(risk_category='MEDIUM').count(),
        'HIGH': ScanResult.query.filter_by(risk_category='HIGH').count(),
        'CRITICAL': ScanResult.query.filter_by(risk_category='CRITICAL').count()
    }

    # 3. Top indicators from ScanFinding
    top_indicators_query = (
        db.session.query(
            ScanFinding.indicator_type,
            func.count(ScanFinding.id).label('count')
        )
        .group_by(ScanFinding.indicator_type)
        .order_by(desc('count'))
        .limit(10)
        .all()
    )

    top_indicators = [
        {
            'indicator_type': row[0],
            'count': row[1]
        }
        for row in top_indicators_query
    ]

    # 4. Weekly trends for last 8 weeks
    weekly_trends = []
    for week_idx in range(7, -1, -1):
        week_end = now - timedelta(days=week_idx * 7)
        week_start = week_end - timedelta(days=7)
        week_label = f"{week_start.strftime('%b %d')} - {week_end.strftime('%b %d')}"

        week_scans = ScanResult.query.filter(
            ScanResult.scan_timestamp >= week_start,
            ScanResult.scan_timestamp < week_end
        ).all()

        total = len(week_scans)
        phishing = sum(
            1 for s in week_scans
            if s.risk_category in ['HIGH', 'CRITICAL'] or s.ai_verdict == 'PHISHING'
        )

        weekly_trends.append({
            'week': f"W-{week_idx}",
            'date_range': week_label,
            'total': total,
            'phishing': phishing,
            'safe': total - phishing
        })

    return {
        'daily_counts': daily_counts,
        'category_distribution': category_counts,
        'top_indicators': top_indicators,
        'weekly_trends': weekly_trends
    }


def get_setting(key, default=None):
    """
    Retrieve setting value from AppSettings table.
    """
    setting = db.session.get(AppSettings, key)
    if setting and setting.value is not None:
        return setting.value
    return default


def set_setting(key, value, description=None):
    """
    Upsert an application setting.
    """
    setting = db.session.get(AppSettings, key)
    if setting:
        setting.value = str(value)
        if description:
            setting.description = description
    else:
        setting = AppSettings(
            key=key,
            value=str(value),
            description=description
        )
        db.session.add(setting)

    db.session.commit()
    return setting.to_dict()


def get_all_settings():
    """
    Retrieve all application settings as a dictionary {key: value}.
    """
    settings = AppSettings.query.all()
    return {item.key: item.value for item in settings}
