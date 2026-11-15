from datetime import timezone

from sqlalchemy import case, func, select

from .models import Alert, Incident, Indicator, RiskSnapshot, now, uid
from .persistence import insert_for
from .security import audit


def capture(db, at=None):
    captured = at or now()
    if captured.tzinfo is None:
        raise ValueError('Snapshot timestamp requires a timezone')
    captured = captured.astimezone(timezone.utc)
    bucket = captured.replace(minute=0, second=0, microsecond=0)
    existing = db.scalar(select(RiskSnapshot).where(RiskSnapshot.bucket_start == bucket))
    if existing:
        return existing
    count, risk, high = db.execute(select(func.count(), func.avg(Indicator.score), func.sum(case((Indicator.score >= 70, 1), else_=0))).where(Indicator.status == 'active')).one()
    data = {'model': 'mean-active-ioc-priority-v1', 'risk_score': round(float(risk), 2) if risk is not None else None,
        'active_indicators': count,
        'high_critical': high or 0,
        'alerts': dict(db.execute(select(Alert.state, func.count()).group_by(Alert.state)).all()),
        'incidents': dict(db.execute(select(Incident.state, func.count()).group_by(Incident.state)).all())}
    identifier = db.scalar(insert_for(db, RiskSnapshot).values(id=uid(), bucket_start=bucket, captured_at=captured, data=data).on_conflict_do_nothing(index_elements=['bucket_start']).returning(RiskSnapshot.id))
    if identifier:
        audit(db, None, 'risk.snapshot_captured', identifier, {'bucket_start': bucket.isoformat()})
    return db.scalar(select(RiskSnapshot).where(RiskSnapshot.bucket_start == bucket))
