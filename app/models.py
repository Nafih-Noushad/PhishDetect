from datetime import datetime
import json
from app import db


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    sender = db.Column(db.String(500), nullable=False)
    subject = db.Column(db.String(1000), nullable=False)
    body_preview = db.Column(db.String(500), nullable=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_category = db.Column(db.String(20), nullable=False, default='LOW')
    ai_verdict = db.Column(db.String(50), nullable=False, default='UNAVAILABLE')
    ai_confidence = db.Column(db.Float, nullable=True, default=0.0)
    ai_uncertainty = db.Column(db.String(20), nullable=True, default='high')
    ai_reasons = db.Column(db.Text, nullable=True)
    rule_score = db.Column(db.Integer, nullable=False, default=0)
    ai_score = db.Column(db.Integer, nullable=False, default=0)
    ollama_available = db.Column(db.Boolean, default=False, nullable=False)
    model_used = db.Column(db.String(100), nullable=True)
    recommended_actions = db.Column(db.Text, nullable=True)
    full_result = db.Column(db.Text, nullable=True)

    findings = db.relationship(
        'ScanFinding',
        backref='scan',
        cascade='all, delete-orphan',
        lazy=True,
        order_by='ScanFinding.id'
    )

    def to_dict(self):
        def _safe_json_loads(val, fallback):
            if val is None:
                return fallback
            if isinstance(val, (dict, list)):
                return val
            try:
                return json.loads(val)
            except Exception:
                return fallback

        return {
            'id': self.id,
            'scan_timestamp': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'sender': self.sender,
            'subject': self.subject,
            'body_preview': self.body_preview,
            'risk_score': self.risk_score,
            'risk_category': self.risk_category,
            'ai_verdict': self.ai_verdict,
            'ai_confidence': self.ai_confidence,
            'ai_uncertainty': self.ai_uncertainty,
            'ai_reasons': _safe_json_loads(self.ai_reasons, []),
            'rule_score': self.rule_score,
            'ai_score': self.ai_score,
            'ollama_available': self.ollama_available,
            'model_used': self.model_used,
            'recommended_actions': _safe_json_loads(self.recommended_actions, []),
            'full_result': _safe_json_loads(self.full_result, {}),
            'findings': [f.to_dict() for f in self.findings] if self.findings else []
        }

    def __repr__(self):
        return f'<ScanResult id={self.id} sender={self.sender!r} risk={self.risk_category}>'


class ScanFinding(db.Model):
    __tablename__ = 'scan_findings'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(
        db.Integer,
        db.ForeignKey('scan_results.id', ondelete='CASCADE'),
        nullable=False
    )
    indicator_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    points = db.Column(db.Integer, nullable=False, default=0)

    def to_dict(self):
        evidence_val = self.evidence
        if isinstance(evidence_val, str):
            try:
                evidence_val = json.loads(evidence_val)
            except Exception:
                pass

        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'indicator_type': self.indicator_type,
            'description': self.description,
            'evidence': evidence_val,
            'points': self.points
        }

    def __repr__(self):
        return f'<ScanFinding id={self.id} scan_id={self.scan_id} type={self.indicator_type}>'


class AppSettings(db.Model):
    __tablename__ = 'app_settings'

    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(500), nullable=True)

    def to_dict(self):
        return {
            'key': self.key,
            'value': self.value,
            'description': self.description
        }

    def __repr__(self):
        return f'<AppSettings key={self.key!r}>'


# Model aliases for flexible naming conventions across components and test suites
Scan = ScanResult
Finding = ScanFinding
Setting = AppSettings
