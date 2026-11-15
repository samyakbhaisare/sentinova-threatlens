#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_password="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE threatlens LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE threatlens TO threatlens;
GRANT USAGE ON SCHEMA public TO threatlens;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO threatlens;
SQL
