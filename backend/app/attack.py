import hashlib
import json
import re
from datetime import datetime, timezone

from sqlalchemy import and_, delete, func, select, update

from .models import AttackTechnique, Indicator, TechniqueMapping
from .persistence import insert_for

REFERENCE_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
TECHNIQUE_ID = re.compile(r'T\d{4}(?:\.\d{3})?')


def parse_catalog(text):
    payload = json.loads(text)
    if payload.get('type') != 'bundle' or not isinstance(payload.get('objects'), list):
        raise ValueError('Expected MITRE STIX bundle')
    result = {}
    for obj in payload['objects']:
        if obj.get('type') != 'attack-pattern':
            continue
        ids = [ref.get('external_id') for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack']
        if not ids or not isinstance(ids[0], str) or not TECHNIQUE_ID.fullmatch(ids[0]):
            raise ValueError('Invalid ATT&CK reference identifier')
        technique_id = ids[0]
        modified = datetime.fromisoformat(obj['modified'].replace('Z', '+00:00'))
        if modified.tzinfo is None or not isinstance(obj.get('name'), str) or not 1 <= len(obj['name']) <= 300:
            raise ValueError('Invalid ATT&CK reference metadata')
        if not isinstance(obj.get('id'), str) or not obj['id'].startswith('attack-pattern--'):
            raise ValueError('Invalid ATT&CK STIX identity')
        for key in ('revoked', 'x_mitre_deprecated'):
            if key in obj and not isinstance(obj[key], bool):
                raise ValueError('Invalid ATT&CK lifecycle flag')
        platforms = obj.get('x_mitre_platforms', [])
        if not isinstance(platforms, list) or any(not isinstance(value, str) for value in platforms):
            raise ValueError('Invalid ATT&CK platform list')
        entry = {'technique_id': technique_id, 'stix_id': obj['id'], 'name': obj['name'],
            'description': str(obj.get('description', ''))[:100000],
            'tactics': sorted({phase['phase_name'] for phase in obj.get('kill_chain_phases', []) if phase.get('kill_chain_name') == 'mitre-attack'}),
            'platforms': obj.get('x_mitre_platforms', []), 'revoked': obj.get('revoked', False),
            'deprecated': obj.get('x_mitre_deprecated', False), 'modified_at': modified.astimezone(timezone.utc),
            'known': True, 'catalog_present': True, 'source_url': REFERENCE_URL}
        previous = result.get(technique_id)
        if previous is None or previous['modified_at'] < entry['modified_at']:
            result[technique_id] = entry
    if not result or len(result) > 50000:
        raise ValueError('Empty or oversized technique catalog')
    return result, hashlib.sha256(text.encode()).hexdigest()


def replace_mappings(db, indicator_id, identifiers):
    identifiers = sorted(set(identifiers))
    if any(not TECHNIQUE_ID.fullmatch(value) for value in identifiers):
        raise ValueError('Invalid ATT&CK mapping')
    for identifier in identifiers:
        # An unresolved analyst assertion stores only its ID; no name or reference
        # content is invented. Synchronization resolves it against actual STIX data.
        db.execute(insert_for(db, AttackTechnique).values(technique_id=identifier).on_conflict_do_nothing(index_elements=['technique_id']))
    db.execute(delete(TechniqueMapping).where(TechniqueMapping.indicator_id == indicator_id))
    for identifier in identifiers:
        db.add(TechniqueMapping(indicator_id=indicator_id, technique_id=identifier))


def synchronize(db, text):
    entries, checksum = parse_catalog(text)  # Validate everything before mutations.
    db.execute(update(AttackTechnique).where(AttackTechnique.known.is_(True)).values(catalog_present=False))
    for identifier, entry in entries.items():
        statement = insert_for(db, AttackTechnique).values(**entry)
        db.execute(statement.on_conflict_do_update(index_elements=['technique_id'], set_={k:v for k,v in entry.items() if k != 'technique_id'}))
    # Stream legacy JSON mappings in bounded pages; references remain normalized.
    last = ''
    while True:
        rows = db.execute(select(Indicator.id, Indicator.techniques).where(Indicator.id > last).order_by(Indicator.id).limit(500)).all()
        if not rows:
            break
        for identifier, mappings in rows:
            replace_mappings(db, identifier, mappings)
        db.flush()
        last = rows[-1][0]
    return len(entries), checksum


def coverage(db):
    query = select(AttackTechnique, func.count(Indicator.id)).outerjoin(TechniqueMapping, TechniqueMapping.technique_id == AttackTechnique.technique_id).outerjoin(
        Indicator, and_(Indicator.id == TechniqueMapping.indicator_id, Indicator.status == 'active')).group_by(AttackTechnique.technique_id).order_by(AttackTechnique.technique_id)
    items = []
    for technique, count in db.execute(query.execution_options(populate_existing=True)):
        items.append({'technique_id': technique.technique_id, 'name': technique.name, 'tactics': technique.tactics,
            'active_indicators': count, 'known': technique.known, 'catalog_present': technique.catalog_present,
            'revoked': technique.revoked, 'deprecated': technique.deprecated, 'modified_at': technique.modified_at,
            'reference_url': 'https://attack.mitre.org/techniques/' + technique.technique_id.replace('.', '/') + '/' if technique.known else None})
    active = [item for item in items if item['known'] and item['catalog_present'] and not item['revoked'] and not item['deprecated']]
    return {'items': items, 'active_reference_count': len(active), 'observed_count': sum(item['active_indicators'] > 0 for item in active),
            'metric': 'Active intelligence mapped to techniques; zero means no mapped IOC, not proof of absent detection'}
