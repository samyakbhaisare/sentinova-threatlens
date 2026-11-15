"""Build (or resume) the isolated large synthetic index used by NFR-03/NFR-05.

The index lives on the isolated benchmark Elasticsearch instance (default
``http://127.0.0.1:9202``), never on production search.  Runs are resumable: if
the process is interrupted, re-running continues from the current document
count instead of rebuilding from zero.
"""
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from nfr_common import build_search_index, hardware

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('SEARCH_URL',):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')

BASE = os.environ.get('SEARCH_URL', 'http://127.0.0.1:9202')
INDEX = os.environ.get('NFR_SEARCH_INDEX', 'threatlens_nfr_10m')
DOCS = int(os.environ.get('NFR_SEARCH_DOCS', '10000000'))
BATCH = int(os.environ.get('NFR_SEARCH_BATCH', '10000'))
RUN = 'nfr-index-' + time.strftime('%Y%m%d-%H%M%S')


def main():
    started = time.perf_counter()
    stats = build_search_index(BASE, INDEX, DOCS, BATCH)
    result = {'run': RUN, 'hardware': hardware(), 'search_url': BASE, 'index': INDEX,
              'target_documents': DOCS, **stats,
              'wall_seconds': round(time.perf_counter() - started, 1),
              'isolation': 'isolated benchmark Elasticsearch only'}
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-search-index.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
