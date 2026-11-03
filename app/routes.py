import os
import json
import time
from functools import wraps
from datetime import datetime

from flask import (
    Blueprint, render_template, request, jsonify,
    session, redirect, url_for, Response, current_app, abort
)

from app import db
from app.models import ScanResult, ScanFinding
from app.database import (
    get_scan_by_id, get_all_scans, delete_scan, clear_all_scans,
    get_stats, get_analytics_data, get_setting, set_setting, get_all_settings
)
from app.validators import validate_email_input, validate_settings_input
from app.detection_engine import PhishingDetectionEngine
from app.risk_scoring import build_score_report
from app.ollama_service import get_ollama_service

main = Blueprint('main', __name__)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'message': 'Not authenticated'}), 401
            return redirect(url_for('main.login_page'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@main.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('main.dashboard_page'))
    return redirect(url_for('main.login_page'))


@main.route('/login', methods=['GET'])
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('main.dashboard_page'))
    return render_template('login.html')


@main.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', '')).strip()

    demo_email = os.getenv('DEMO_EMAIL', 'admin@phishdetect.ai').strip().lower()
    demo_password = os.getenv('DEMO_PASSWORD', 'admin123').strip()

    if email == demo_email and password == demo_password:
        session.clear()
        session['logged_in'] = True
        session['email'] = email
        return jsonify({
            'success': True,
            'message': 'Login successful.',
            'redirect': url_for('main.dashboard_page')
        })

    return jsonify({
        'success': False,
        'message': 'Invalid email address or password.'
    }), 401


@main.route('/logout', methods=['GET', 'POST'], endpoint='logout')
@main.route('/api/logout', methods=['GET', 'POST'], endpoint='api_logout')
def api_logout():
    session.clear()
    if request.path.startswith('/api/') and request.method == 'POST':
        return jsonify({'success': True, 'message': 'Logged out successfully.'})
    return redirect(url_for('main.login_page'))


# ============================================================================
# PAGE ROUTES (HTML)
# ============================================================================

@main.route('/dashboard', methods=['GET'], endpoint='dashboard')
@main.route('/dashboard', methods=['GET'], endpoint='dashboard_page')
@login_required
def dashboard_page():
    return render_template('dashboard.html', email=session.get('email'))


@main.route('/analyze', methods=['GET'])
@login_required
def analyze_page():
    return render_template('analyze.html', email=session.get('email'))


@main.route('/results/<int:scan_id>', methods=['GET'])
@login_required
def results_page(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
    scan_dict = scan.to_dict()
    return render_template(
        'results.html',
        scan_id=scan_id,
        scan_data=scan_dict,
        scan=scan_dict,
        scan_json=json.dumps(scan_dict),
        email=session.get('email')
    )


@main.route('/history', methods=['GET'])
@login_required
def history_page():
    return render_template('history.html', email=session.get('email'))


@main.route('/analytics', methods=['GET'])
@login_required
def analytics_page():
    return render_template('analytics.html', email=session.get('email'))


@main.route('/settings', methods=['GET'])
@login_required
def settings_page():
    return render_template('settings.html', email=session.get('email'))


@main.route('/about', methods=['GET'])
@login_required
def about_page():
    return render_template('about.html', email=session.get('email'))


# ============================================================================
# API ROUTES (JSON)
# ============================================================================

@main.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    stats = get_stats()
    return jsonify({
        'success': True,
        'stats': stats
    })


@main.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    sender = data.get('sender')
    subject = data.get('subject')
    body = data.get('body')

    # 1. Validate inputs
    is_valid, cleaned, error_msg = validate_email_input(sender, subject, body)
    if not is_valid:
        return jsonify({
            'success': False,
            'message': error_msg
        }), 400

    clean_sender = cleaned['sender']
    clean_subject = cleaned['subject']
    clean_body = cleaned['body']

    # 2. Run rule-based heuristic detection engine
    engine = PhishingDetectionEngine()
    rule_findings = engine.analyze(
        sender=clean_sender,
        subject=clean_subject,
        body=clean_body
    )

    # 3. Ollama AI Semantic Analysis
    ollama_svc = get_ollama_service()
    ai_response = ollama_svc.analyze_email(
        sender=clean_sender,
        subject=clean_subject,
        body=clean_body
    )

    if ai_response.get('success') and ai_response.get('result'):
        ollama_available = True
        ai_result = ai_response['result']
        model_used = ollama_svc.model
    else:
        ollama_available = False
        err = ai_response.get('error') or 'Service offline'
        ai_result = {
            'verdict': 'UNAVAILABLE',
            'reasons': [f"Ollama AI analysis unavailable: {err}"],
            'evidence': [],
            'confidence': 0.0,
            'uncertainty': 'high',
            'recommended_actions': [
                "Heuristic security rules applied successfully.",
                "Verify suspicious links and sender addresses independently."
            ]
        }
        model_used = None

    # 4. Calculate final risk scores & build report
    score_report = build_score_report(rule_findings, ai_result)

    # 5. Persist to Database
    body_preview = (clean_body[:200] + '...') if len(clean_body) > 200 else clean_body

    full_result_payload = {
        'rule_findings': rule_findings,
        'ai_result': ai_result,
        'score_report': score_report,
        'ollama_available': ollama_available,
        'model_used': model_used
    }

    scan = ScanResult(
        sender=clean_sender,
        subject=clean_subject,
        body_preview=body_preview,
        risk_score=score_report['final_score'],
        risk_category=score_report['risk_category'],
        ai_verdict=ai_result['verdict'],
        ai_confidence=ai_result.get('confidence', 0.0),
        ai_uncertainty=ai_result.get('uncertainty', 'medium'),
        ai_reasons=json.dumps(ai_result.get('reasons', [])),
        rule_score=score_report['rule_score'],
        ai_score=score_report['ai_score'],
        ollama_available=ollama_available,
        model_used=model_used,
        recommended_actions=json.dumps(ai_result.get('recommended_actions', [])),
        full_result=json.dumps(full_result_payload)
    )

    db.session.add(scan)
    db.session.flush()  # Populate scan.id

    # Persist findings
    for finding in rule_findings:
        sf = ScanFinding(
            scan_id=scan.id,
            indicator_type=finding['indicator_type'],
            description=finding['description'],
            evidence=json.dumps(finding.get('evidence', [])),
            points=finding.get('points', 0)
        )
        db.session.add(sf)

    db.session.commit()

    return jsonify({
        'success': True,
        'scan_id': scan.id,
        'risk_score': scan.risk_score,
        'risk_category': scan.risk_category,
        'ai_verdict': scan.ai_verdict,
        'ai_confidence': scan.ai_confidence,
        'ai_uncertainty': scan.ai_uncertainty,
        'ai_reasons': ai_result.get('reasons', []),
        'ai_evidence': ai_result.get('evidence', []),
        'ai_recommended_actions': ai_result.get('recommended_actions', []),
        'ollama_available': scan.ollama_available,
        'model_used': scan.model_used,
        'rule_findings': rule_findings,
        'score_breakdown': score_report['score_breakdown'],
        'rule_score': scan.rule_score,
        'ai_score': scan.ai_score,
        'sender': scan.sender,
        'subject': scan.subject,
        'scan_timestamp': scan.scan_timestamp.isoformat()
    })


@main.route('/api/scan/<int:scan_id>', methods=['GET'])
@login_required
def api_get_scan(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({
            'success': False,
            'message': f"Scan with ID {scan_id} not found."
        }), 404

    return jsonify({
        'success': True,
        'scan': scan.to_dict()
    })


@main.route('/api/history', methods=['GET'])
@login_required
def api_history():
    page = request.args.get('page', 1, type=int)
    per_page = min(50, max(1, request.args.get('per_page', 10, type=int)))
    search = request.args.get('search', None)
    category = request.args.get('category', None)
    sort_by = request.args.get('sort_by', 'scan_timestamp')
    sort_dir = request.args.get('sort_dir', 'desc')

    result = get_all_scans(
        page=page,
        per_page=per_page,
        search=search,
        category=category,
        sort_by=sort_by,
        sort_dir=sort_dir
    )

    # Transform scan items to summary format as specified
    scans_summary = []
    for s in result['scans']:
        scans_summary.append({
            'id': s['id'],
            'scan_timestamp': s['scan_timestamp'],
            'sender': s['sender'],
            'subject': s['subject'],
            'risk_score': s['risk_score'],
            'risk_category': s['risk_category'],
            'ai_verdict': s['ai_verdict'],
            'ai_confidence': s['ai_confidence'],
            'ollama_available': s['ollama_available']
        })

    return jsonify({
        'success': True,
        'scans': scans_summary,
        'total': result['total'],
        'page': result['page'],
        'per_page': result['per_page'],
        'pages': result['pages']
    })


@main.route('/api/history/<int:scan_id>', methods=['DELETE'])
@login_required
def api_delete_scan(scan_id):
    deleted = delete_scan(scan_id)
    if not deleted:
        return jsonify({
            'success': False,
            'message': f"Scan with ID {scan_id} was not found."
        }), 404
    return jsonify({
        'success': True,
        'message': f"Scan {scan_id} successfully deleted."
    })


@main.route('/api/history', methods=['DELETE'])
@login_required
def api_clear_history():
    count = clear_all_scans()
    return jsonify({
        'success': True,
        'deleted': count,
        'message': f"All {count} scan records have been cleared."
    })


@main.route('/api/analytics', methods=['GET'])
@login_required
def api_analytics():
    data = get_analytics_data()
    return jsonify({
        'success': True,
        'data': data
    })


@main.route('/api/settings', methods=['GET'])
@login_required
def api_get_settings():
    ollama_url = get_setting('ollama_url', os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'))
    ollama_model = get_setting('ollama_model', os.getenv('OLLAMA_MODEL', 'llama3.2'))
    app_version = get_setting('app_version', '1.0.0')
    db_path = os.path.join(current_app.instance_path, 'phishdetect.db')
    total_scans = ScanResult.query.count()

    return jsonify({
        'success': True,
        'ollama_url': ollama_url,
        'ollama_model': ollama_model,
        'app_version': app_version,
        'db_path': db_path,
        'total_scans': total_scans
    })


@main.route('/api/settings', methods=['POST'])
@login_required
def api_save_settings():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    ollama_url = data.get('ollama_url')
    ollama_model = data.get('ollama_model')

    is_valid, cleaned, error_msg = validate_settings_input(ollama_url, ollama_model)
    if not is_valid:
        return jsonify({
            'success': False,
            'message': error_msg
        }), 400

    set_setting('ollama_url', cleaned['ollama_url'], 'Ollama API endpoint URL')
    set_setting('ollama_model', cleaned['ollama_model'], 'Ollama AI model identifier')

    return jsonify({
        'success': True,
        'message': 'Settings updated successfully.'
    })


@main.route('/api/ollama/status', methods=['GET'])
@login_required
def api_ollama_status():
    svc = get_ollama_service()
    status = svc.check_connection()
    return jsonify({
        'success': True,
        'connected': status['connected'],
        'error': status['error'],
        'models': status['models'],
        'current_model': svc.model
    })


@main.route('/api/ollama/models', methods=['GET'])
@login_required
def api_ollama_models():
    svc = get_ollama_service()
    models = svc.list_models()
    return jsonify({
        'success': True,
        'models': models
    })


@main.route('/api/ollama/test', methods=['POST'])
@login_required
def api_ollama_test():
    svc = get_ollama_service()
    start = time.time()
    test_result = svc.analyze_email(
        sender="security-alert@example-service.com",
        subject="Important: Security Verification Needed",
        body="Dear customer, please click here to verify your account login credentials immediately."
    )
    elapsed_ms = int((time.time() - start) * 1000)

    if test_result['success']:
        return jsonify({
            'success': True,
            'message': f"Ollama model '{svc.model}' responded successfully.",
            'response_time_ms': elapsed_ms
        })
    else:
        return jsonify({
            'success': False,
            'message': test_result['error'] or 'Test generation failed.',
            'response_time_ms': elapsed_ms
        }), 502


@main.route('/api/export/<int:scan_id>', methods=['GET'])
@login_required
def api_export_scan(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({
            'success': False,
            'message': f"Scan {scan_id} not found."
        }), 404

    export_format = request.args.get('format', 'json').lower()
    scan_data = scan.to_dict()

    if export_format == 'txt':
        lines = [
            "=" * 60,
            "           PHISHDETECT AI - SCAN ANALYSIS REPORT",
            "=" * 60,
            f"Scan ID:          {scan.id}",
            f"Timestamp:        {scan.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Sender:           {scan.sender}",
            f"Subject:          {scan.subject}",
            f"Risk Score:       {scan.risk_score} / 100",
            f"Risk Category:    {scan.risk_category}",
            f"AI Verdict:       {scan.ai_verdict} (Confidence: {round(float(scan.ai_confidence or 0)*100)}%)",
            f"Rule Score:       {scan.rule_score} / 60",
            f"AI Score:         {scan.ai_score} / 40",
            f"Model Used:       {scan.model_used or 'N/A'}",
            "-" * 60,
            "HEURISTIC RULE FINDINGS:",
        ]
        if scan.findings:
            for idx, f in enumerate(scan.findings, 1):
                lines.append(f"  {idx}. [{f.indicator_type}] (+{f.points} pts)")
                lines.append(f"     Description: {f.description}")
                ev_list = f.to_dict().get('evidence', [])
                if ev_list:
                    lines.append("     Evidence:")
                    if isinstance(ev_list, list):
                        for ev in ev_list:
                            lines.append(f"       * {ev}")
                    else:
                        lines.append(f"       * {ev_list}")
        else:
            lines.append("  No heuristic risk indicators triggered.")

        lines.extend([
            "-" * 60,
            "AI ANALYSIS REASONS:",
        ])
        for r in scan_data.get('ai_reasons', []):
            lines.append(f"  * {r}")

        lines.extend([
            "-" * 60,
            "RECOMMENDED ACTIONS:",
        ])
        for a in scan_data.get('recommended_actions', []):
            lines.append(f"  * {a}")

        lines.append("=" * 60)
        txt_content = "\n".join(lines)

        return Response(
            txt_content,
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename=phishdetect_scan_{scan_id}.txt"}
        )

    # Default: JSON export
    return Response(
        json.dumps(scan_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=phishdetect_scan_{scan_id}.json"}
    )


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@main.app_errorhandler(404)
def handle_404(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({
            'success': False,
            'message': 'Resource not found'
        }), 404
    return render_template('login.html', error="Page not found"), 404


@main.app_errorhandler(500)
def handle_500(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({
            'success': False,
            'message': 'Internal server error occurred'
        }), 500
    return render_template('login.html', error="Internal server error"), 500
