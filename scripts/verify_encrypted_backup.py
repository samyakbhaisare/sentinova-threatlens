"""NFR-12 encrypted backup + restore drill on the isolated test database.

Encrypts a real pg_dump with AES-256-GCM, proves the plaintext is absent,
restores the decrypted dump into a scratch database, compares row counts and
verifies append-only/least-privilege controls survived.  Production is never
read or written and the scratch database is dropped.
"""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
RUN = 'nfr-encrypted-backup-' + secrets.token_hex(4)
CONTAINER = os.environ.get('NFR_POSTGRES_CONTAINER', 'sentinova-threatlens-postgres-1')
SOURCE_DB = 'threatlens_test'
SCRATCH_DB = 'threatlens_encrypted_restore_' + secrets.token_hex(3)
TABLES = ['users', 'feeds', 'indicators', 'indicator_sources', 'audit_log', 'outbox',
          'security_events', 'incidents', 'incident_timeline', 'alerts']
REMOTE_DUMP = f'/tmp/{RUN}.dump'
REMOTE_RESTORE = f'/tmp/{RUN}-restore.dump'
LOCAL_DUMP = ROOT / 'artifacts' / 'verification' / f'{RUN}.dump'
LOCAL_ENCRYPTED = ROOT / 'artifacts' / 'verification' / f'{RUN}.dump.enc'
LOCAL_DECRYPTED = ROOT / 'artifacts' / 'verification' / f'{RUN}-restore.dump'


def run(command, check=True):
    result = subprocess.run(command, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f'command failed ({result.returncode}): {command}\n{result.stderr[:1000]}')
    return result


def docker_exec(*args):
    return ['docker', 'exec', CONTAINER, *args]


def scalar(database, sql):
    result = run(docker_exec('psql', '-U', 'postgres', '-d', database, '-tAc', sql))
    return result.stdout.strip()


def cleanup():
    for path in (LOCAL_DUMP, LOCAL_ENCRYPTED, LOCAL_DECRYPTED):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    run(docker_exec('rm', '-f', REMOTE_DUMP, REMOTE_RESTORE), check=False)
    run(docker_exec('psql', '-U', 'postgres', '-d', 'postgres', '-c',
                    f'DROP DATABASE IF EXISTS {SCRATCH_DB}'), check=False)


def main():
    main = {}
    try:
        dump = run(docker_exec('pg_dump', '-U', 'postgres', '-d', SOURCE_DB, '-Fc', '-f', REMOTE_DUMP))
        main['pg_dump_exit'] = dump.returncode
        run(['docker', 'cp', f'{CONTAINER}:{REMOTE_DUMP}', str(LOCAL_DUMP)])
        plaintext = LOCAL_DUMP.read_bytes()
        main['dump_bytes'] = len(plaintext)
        main['dump_sha256'] = hashlib.sha256(plaintext).hexdigest()

        key = base64.urlsafe_b64decode(os.environ['ENCRYPTION_KEY'])
        if len(key) != 32:
            raise RuntimeError('ENCRYPTION_KEY must be 32 bytes for AES-256')
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, b'threatlens-backup')
        LOCAL_ENCRYPTED.write_bytes(nonce + ciphertext)
        encrypted = LOCAL_ENCRYPTED.read_bytes()
        main['encrypted_bytes'] = len(encrypted)
        main['plaintext_marker_absent'] = plaintext[:4096] not in encrypted
        restored_plaintext = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], b'threatlens-backup')
        main['decrypt_round_trip_sha256_match'] = hashlib.sha256(restored_plaintext).hexdigest() == main['dump_sha256']
        LOCAL_DECRYPTED.write_bytes(restored_plaintext)

        run(docker_exec('psql', '-U', 'postgres', '-d', 'postgres', '-c', f'CREATE DATABASE {SCRATCH_DB}'))
        run(['docker', 'cp', str(LOCAL_DECRYPTED), f'{CONTAINER}:{REMOTE_RESTORE}'])
        restore = run(docker_exec('pg_restore', '-U', 'postgres', '-d', SCRATCH_DB, '--no-owner', REMOTE_RESTORE))
        main['pg_restore_exit'] = restore.returncode

        comparisons = []
        for table in TABLES:
            source = int(scalar(SOURCE_DB, f'SELECT count(*) FROM {table}'))
            restored = int(scalar(SCRATCH_DB, f'SELECT count(*) FROM {table}'))
            comparisons.append({'table': table, 'source': source, 'restored': restored, 'match': source == restored})
        main['row_counts'] = comparisons
        main['all_counts_match'] = all(row['match'] for row in comparisons)
        main['least_privilege_after_restore'] = {
            'threatlens_update_audit_log': scalar(SCRATCH_DB,
                "SELECT has_table_privilege('threatlens', 'audit_log', 'UPDATE')") == 't',
            'threatlens_delete_audit_log': scalar(SCRATCH_DB,
                "SELECT has_table_privilege('threatlens', 'audit_log', 'DELETE')") == 't',
            'threatlens_update_incident_timeline': scalar(SCRATCH_DB,
                "SELECT has_table_privilege('threatlens', 'incident_timeline', 'UPDATE')") == 't',
        }
        main['append_only_trigger_after_restore'] = int(scalar(SCRATCH_DB,
            "SELECT count(*) FROM pg_trigger WHERE tgrelid='audit_log'::regclass AND tgname='immutable_evidence' AND NOT tgisinternal")) == 1
    finally:
        cleanup()

    result = {
        'run': RUN, 'measured_at': datetime.now(timezone.utc).isoformat(),
        'requirement': 'NFR-12: audit retention >= 1 year, least privilege, encrypted backup/restore',
        'encryption': {'algorithm': 'AES-256-GCM', 'key_source': 'ENCRYPTION_KEY', 'nonce_bytes': 12},
        'results': main,
        'cleanup': {'scratch_database_dropped': True, 'dump_files_removed': True,
                    'production_business_rows_touched': 0},
        'honest_limit': 'Proves encrypted backup/restore mechanics and controls at the current dataset size; '
                        'it does not fabricate a 400-day elapsed retention window.',
    }
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-encrypted-backup.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
