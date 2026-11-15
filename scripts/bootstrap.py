"""Generate local-only credentials without printing them; never overwrite existing secrets."""
import base64
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
target = root / '.env'
if target.exists():
    raise SystemExit('.env already exists; preserving it')
password = secrets.token_urlsafe(32)
owner_password = secrets.token_urlsafe(32)
content = '\n'.join([
    'POSTGRES_PASSWORD=' + owner_password,
    'APP_DB_PASSWORD=' + password,
    f'DATABASE_URL=postgresql+psycopg://threatlens:{password}@127.0.0.1:5433/threatlens',
    'REDIS_URL=redis://127.0.0.1:6380/0',
    'SEARCH_URL=http://127.0.0.1:9201',
    'JWT_SECRET=' + secrets.token_urlsafe(48),
    'ENCRYPTION_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    'ORIGIN=http://localhost:3000',
    'PRODUCTION=false',
    'REPORT_DIR=' + (root / 'artifacts' / 'reports').as_posix(),
    'SECRETS_DIR=' + (root / 'secrets').as_posix(),
])
target.write_text(content + '\n')
(root / 'secrets').mkdir(exist_ok=True)
(root / 'artifacts').mkdir(exist_ok=True)
print('Generated private local .env. No user accounts or threat data created.')
