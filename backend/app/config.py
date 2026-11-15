from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    database_url: str = 'postgresql+psycopg://threatlens@localhost:5432/threatlens'
    redis_url: str = 'redis://localhost:6379/0'
    search_url: str = 'http://localhost:9200'
    jwt_secret: str = ''
    jwt_secret_file: str = ''
    encryption_key: str = ''
    encryption_key_file: str = ''
    production: bool = False
    origin: str = 'http://localhost:3000'
    secrets_dir: str = '/run/secrets'
    report_dir: str = '/data/reports'
    feed_hosts: str = 'www.cisa.gov,feodotracker.abuse.ch,urlhaus-api.abuse.ch,mb-api.abuse.ch,threatfox-api.abuse.ch,otx.alienvault.com,raw.githubusercontent.com,www.spamhaus.org'
    test_mode: bool = False
    automatic_enrichment: bool = True
    geolocation_enabled: bool = False
    # Provider endpoints are operator-overridable so an enterprise deployment can
    # front them with an egress proxy or run the documented conformance servers.
    # Defaults are the public vendor endpoints; credentials are never in the URL.
    virustotal_base_url: str = 'https://www.virustotal.com/api/v3/'
    abuseipdb_base_url: str = 'https://api.abuseipdb.com/api/v2/'
    ipwhois_base_url: str = 'https://ipwho.is/'
    search_index: str = Field(default='threatlens', pattern=r'^[a-z][a-z0-9_-]{0,100}$')
    db_pool_size: int = Field(default=5, ge=1, le=100)
    db_max_overflow: int = Field(default=10, ge=0, le=200)

    def secret(self, name: str) -> str:
        if not name or not name.replace('_', '').isalnum():
            return ''
        directory = Path(self.secrets_dir)
        path = directory / name
        if path.is_file():
            return path.read_text().strip()
        # AES-256-GCM encrypted secret file (NFR-06 / PRD 13.3). The ciphertext
        # never contains the credential in plaintext; only the app key can open it.
        encrypted = directory / f'{name}.enc'
        if encrypted.is_file():
            from .security import decrypt
            return decrypt(encrypted.read_text().strip())
        return ''

    def signing_key(self) -> str:
        key = Path(self.jwt_secret_file).read_text().strip() if self.jwt_secret_file else self.jwt_secret
        if len(key) < 32:
            raise RuntimeError('JWT secret must contain at least 32 characters')
        return key


@lru_cache
def settings() -> Settings:
    return Settings()
