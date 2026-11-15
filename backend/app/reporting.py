import csv
import io
import json
from pathlib import Path
from html import escape

import stix2
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy import delete, func, select

from .config import settings
from .models import Alert, Feed, Incident, IncidentLink, Indicator, Provenance, Report, ReportItem, Timeline, User
from .classification import highest, incident_label


class ReportPolicyError(ValueError):
    pass


def csv_export(indicators):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(['type', 'value', 'score', 'confidence', 'tlp', 'status', 'tags'])
    for ioc in indicators:
        row = [ioc.type, ioc.value, ioc.score, ioc.confidence, ioc.tlp, ioc.status, ';'.join(ioc.tags)]
        writer.writerow(["'" + v if isinstance(v, str) and (v.lstrip().startswith(('=', '+', '-', '@')) or v.startswith(('\t', '\r', '\n'))) else v for v in row])
    return stream.getvalue()


def stix_export(indicators):
    objects = []
    mapping = {'ip': 'ipv4-addr:value', 'domain': 'domain-name:value', 'url': 'url:value', 'email': 'email-addr:value',
               'hash_md5': "file:hashes.'MD5'", 'hash_sha1': "file:hashes.'SHA-1'", 'hash_sha256': "file:hashes.'SHA-256'"}
    marks = {'green': stix2.TLP_GREEN, 'amber': stix2.TLP_AMBER, 'red': stix2.TLP_RED, 'clear': stix2.TLP_WHITE}
    used = set()
    for ioc in indicators:
        marking = marks[ioc.tlp]
        if marking.id not in used:
            objects.append(marking)
            used.add(marking.id)
        if ioc.type == 'cve':
            objects.append(stix2.Vulnerability(name=ioc.value, external_references=[{'source_name': 'cve', 'external_id': ioc.value}], object_marking_refs=[marking.id]))
        else:
            key = 'ipv6-addr:value' if ioc.type == 'ip' and ':' in ioc.value else mapping[ioc.type]
            value = ioc.value.replace('\\', '\\\\').replace("'", "\\'")
            objects.append(stix2.Indicator(name=ioc.value, pattern=f"[{key} = '{value}']", pattern_type='stix',
                valid_from=ioc.first_seen, confidence=ioc.confidence, object_marking_refs=[marking.id]))
    return json.loads(stix2.Bundle(objects=objects).serialize())


def report_path(identifier):
    # IDs are generated internally and never interpreted as arbitrary paths.
    from uuid import UUID
    return Path(settings().report_dir) / (str(UUID(identifier)) + '.pdf')


def generate(db, report: Report):
    owner = db.get(User, report.owner_id)
    if not owner or not owner.enabled:
        raise ValueError('Report owner is disabled')
    if report.tlp == 'red':
        raise ReportPolicyError('TLP:red reports cannot be exported')
    report.tlp = highest('amber', report.tlp)
    if report.incident_id:
        incident = db.get(Incident, report.incident_id)
        if not incident or owner.role not in ('administrator', 'incident_responder', 'soc_analyst', 'threat_hunter'):
            raise ValueError('Report owner no longer has incident access')
        if owner.role in ('soc_analyst', 'threat_hunter') and owner.id not in (incident.owner_id, incident.creator_id):
            raise ValueError('Report owner no longer has incident context')
        if incident_label(db, incident) == 'red':
            raise ReportPolicyError('TLP:red incident narrative cannot be exported')
        if db.scalar(select(Indicator.id).join(IncidentLink).where(IncidentLink.incident_id == incident.id, Indicator.tlp == 'red').limit(1)):
            raise ReportPolicyError('TLP:red incident reports cannot be exported')
    path = report_path(report.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    db.execute(delete(ReportItem).where(ReportItem.report_id == report.id))
    manifest_count = 0
    story = [Paragraph(escape(report.title), styles['Title']), Paragraph('Sentinova ThreatLens — TLP:AMBER — Internal intelligence report', styles['Normal']), Spacer(1, 16)]
    active = db.scalar(select(func.count()).select_from(Indicator).where(Indicator.status == 'active'))
    risk = db.scalar(select(func.avg(Indicator.score)).where(Indicator.status == 'active'))
    alert_count = db.scalar(select(func.count()).select_from(Alert))
    story.append(Paragraph(f'Executive summary: {active} active indicators, {alert_count} alerts. Mean active intelligence priority: {round(float(risk), 1) if risk is not None else "unavailable"}. This measures IOC priority, not compromise probability.', styles['Normal']))
    if owner.role != 'executive':
        query = select(Indicator).where(Indicator.tlp.in_(['clear', 'green', 'amber'])).order_by(Indicator.score.desc()).limit(500)
        if report.incident_id:
            query = query.join(IncidentLink).where(IncidentLink.incident_id == report.incident_id)
            incident = db.get(Incident, report.incident_id)
            story.append(Paragraph(escape('Incident: ' + incident.title + ' / ' + incident.state), styles['Heading2']))
            for item in db.scalars(select(Timeline).where(Timeline.incident_id == incident.id).order_by(Timeline.created_at, Timeline.id)):
                story.append(Paragraph(escape(f'{item.created_at.isoformat()} {item.kind}: {json.dumps(item.data)}'), styles['Normal']))
        story.append(Paragraph('Technical detail (up to 500 highest-priority non-red indicators)', styles['Heading2']))
        for ioc in db.scalars(query.with_for_update(read=True, of=Indicator)):
            db.add(ReportItem(report_id=report.id, indicator_id=ioc.id, tlp=ioc.tlp, version=ioc.version))
            manifest_count += 1
            story.append(Paragraph(escape(f'{ioc.type}: {ioc.value} | score {ioc.score} | TLP:{ioc.tlp} | {ioc.category}'), styles['Normal']))
            story.append(Paragraph(escape('Score evidence: ' + json.dumps(ioc.breakdown, sort_keys=True)), styles['Normal']))
            for source, feed in db.execute(select(Provenance, Feed).join(Feed).where(Provenance.indicator_id == ioc.id)):
                story.append(Paragraph(escape(f'Source: {feed.name}; confidence {source.confidence}; observed {source.last_seen.isoformat()}; reference {source.reference}'), styles['Normal']))
    SimpleDocTemplate(str(path)).build(story)
    report.state, report.error = 'ready', None
    return {'audience': 'executive' if owner.role == 'executive' else 'operational', 'owner_role': owner.role,
            'manifest_version': 1, 'manifest_count': manifest_count}
