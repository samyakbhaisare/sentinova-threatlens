"""Search projections are rebuildable; failures must leave the DB outbox pending."""
import json

import httpx

from .config import settings


def event_channel():
    return settings().search_index + ':events'


def index_mapping():
    faceted = {'type': 'text', 'fields': {'keyword': {'type': 'keyword', 'ignore_above': 2048}}}
    return {'mappings': {'dynamic': False, 'properties': {
        **{key: faceted for key in ('kind', 'value', 'type', 'status', 'tlp', 'tags', 'techniques', 'category', 'sources', 'source')},
        'id': {'type': 'keyword'}, 'score': {'type': 'integer'}, 'notes': {'type': 'text'},
        'created_at': {'type': 'date'}, 'controlled_test': {'type': 'boolean'},
        'observables': {'properties': {'type': faceted, 'value': faceted}},
        'details': {'type': 'object', 'enabled': False}, 'details_text': {'type': 'text'},
    }}}


def write_documents(documents):
    if not documents:
        return
    config = settings()
    with httpx.Client(timeout=10) as client:
        exists = client.head(f'{config.search_url}/{config.search_index}')
        if exists.status_code == 404:
            created = client.put(f'{config.search_url}/{config.search_index}', json=index_mapping())
            if created.status_code != 400 or created.json().get('error', {}).get('type') != 'resource_already_exists_exception':
                created.raise_for_status()
        else:
            exists.raise_for_status()
        lines = []
        for identifier, document in documents.items():
            lines.extend([json.dumps({'index': {'_index': config.search_index, '_id': identifier}}), json.dumps(document)])
        result = client.post(config.search_url + '/_bulk', content='\n'.join(lines) + '\n', headers={'Content-Type': 'application/x-ndjson'})
        result.raise_for_status()
        if result.json().get('errors'):
            raise RuntimeError('Search bulk projection failed; outbox retained for replay')


def build_query(q='', type=None, source=None, tag=None, technique=None, kind=None, min_score=0):
    filters = [{'range': {'score': {'gte': min_score}}}] if min_score else []
    for field, value in [('type', type), ('tags', tag), ('techniques', technique), ('kind', kind)]:
        if value:
            filters.append({'term': {field + '.keyword': value}})
    if source:
        filters.append({'bool': {'should': [{'term': {'sources.keyword': source}}, {'term': {'source.keyword': source}}], 'minimum_should_match': 1}})
    return {'bool': {'must': [{'simple_query_string': {'query': q, 'fields': ['value^3', 'notes', 'category', 'observables.value', 'details_text'], 'default_operator': 'and'}}] if q else [{'match_all': {}}], 'filter': filters}}
