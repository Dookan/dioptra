-- Runtime role for the API and the worker (P5 day 20, ASVS V7.1 hardening).
--
-- The database is OWNED by POSTGRES_USER, which runs the migrations. The
-- application connects as `dioptra_app`, which can read and write rows but
-- owns nothing: it cannot DROP TRIGGER, ALTER TABLE or otherwise defeat the
-- append-only guarantees of audit_log and report_versions (threat model →
-- Accepted residual risks, resolved here). Runs once, on first init of the
-- data volume; an existing volume needs the same statements by hand.
--
-- Password: `DIOPTRA_APP_DB_PASSWORD` from the Compose environment (.env);
-- the owner and the database from POSTGRES_USER / POSTGRES_DB.
\set app_password `printf '%s' "$DIOPTRA_APP_DB_PASSWORD"`
\set owner `printf '%s' "${POSTGRES_USER:-dioptra}"`
\set dbname `printf '%s' "${POSTGRES_DB:-dioptra}"`
CREATE ROLE dioptra_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE :"dbname" TO dioptra_app;
GRANT USAGE ON SCHEMA public TO dioptra_app;
-- Every table the migrations create afterwards, too.
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO dioptra_app;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO dioptra_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dioptra_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dioptra_app;
