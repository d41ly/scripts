-- this changes db and all it's objects to another owner. Useful with silly HestiaCP's backups.
-- psql -U postgres -d db-name. Or first \c to the correct database as postgres

ALTER DATABASE db-name OWNER TO new-owner;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
        EXECUTE 'ALTER TABLE public.' || quote_ident(r.tablename) || ' OWNER TO new-owner;';
    END LOOP;
END $$;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public') LOOP
        EXECUTE 'ALTER SEQUENCE public.' || quote_ident(r.sequence_name) || ' OWNER TO new-owner;';
    END LOOP;
END $$;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT table_name FROM information_schema.views WHERE table_schema = 'public') LOOP
        EXECUTE 'ALTER VIEW public.' || quote_ident(r.table_name) || ' OWNER TO new-owner;';
    END LOOP;
END $$;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT routine_name, routine_schema FROM information_schema.routines WHERE specific_schema = 'public') LOOP
        EXECUTE 'ALTER FUNCTION ' || quote_ident(r.routine_schema) || '.' || quote_ident(r.routine_name) || ' OWNER TO new-owner;';
    END LOOP;
END $$;

ALTER SCHEMA public OWNER TO new-owner;