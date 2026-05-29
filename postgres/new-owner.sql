ALTER DATABASE db-name OWNER TO new-owner;

DO $$
DECLARE
    new_owner name := 'new-owner';
    r RECORD;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name,
               c.relname AS object_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.%I OWNER TO %I;',
            r.schema_name,
            r.object_name,
            new_owner
        );
    END LOOP;

    FOR r IN
        SELECT n.nspname AS schema_name,
               c.relname AS object_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'S'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format(
            'ALTER SEQUENCE %I.%I OWNER TO %I;',
            r.schema_name,
            r.object_name,
            new_owner
        );
    END LOOP;

    FOR r IN
        SELECT n.nspname AS schema_name,
               c.relname AS object_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'v'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format(
            'ALTER VIEW %I.%I OWNER TO %I;',
            r.schema_name,
            r.object_name,
            new_owner
        );
    END LOOP;

    FOR r IN
        SELECT n.nspname AS schema_name,
               c.relname AS object_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'm'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format(
            'ALTER MATERIALIZED VIEW %I.%I OWNER TO %I;',
            r.schema_name,
            r.object_name,
            new_owner
        );
    END LOOP;

    FOR r IN
        SELECT n.nspname AS schema_name,
               p.proname AS routine_name,
               p.prokind AS routine_kind,
               pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
          AND p.prokind IN ('f', 'w', 'p', 'a')
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_proc'::regclass
                AND d.objid = p.oid
                AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format(
            'ALTER %s %I.%I(%s) OWNER TO %I;',
            CASE r.routine_kind
                WHEN 'p' THEN 'PROCEDURE'
                WHEN 'a' THEN 'AGGREGATE'
                ELSE 'FUNCTION'
            END,
            r.schema_name,
            r.routine_name,
            r.args,
            new_owner
        );
    END LOOP;

    FOR r IN
        SELECT n.nspname AS schema_name,
               t.typname AS type_name
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        LEFT JOIN pg_class c ON c.oid = t.typrelid
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
          AND t.typtype IN ('b', 'c', 'd', 'e', 'm', 'r')
          AND t.typcategory <> 'A'
          AND (
                t.typrelid = 0
                OR c.relkind = 'c'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_type'::regclass
                AND d.objid = t.oid
                AND d.deptype = 'e'
          )
    LOOP
        EXECUTE format(
            'ALTER TYPE %I.%I OWNER TO %I;',
            r.schema_name,
            r.type_name,
            new_owner
        );
    END LOOP;

    FOR r IN
        SELECT n.nspname AS schema_name
        FROM pg_namespace n
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
    LOOP
        EXECUTE format(
            'ALTER SCHEMA %I OWNER TO %I;',
            r.schema_name,
            new_owner
        );
    END LOOP;
END $$;