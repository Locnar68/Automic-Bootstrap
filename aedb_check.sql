select 'pg_version', version();
select 'current_db', current_database(), 'user', current_user;
select 'ext_pgcrypto', count(*) from pg_extension where extname='pgcrypto';
select 'ext_uuid_ossp', count(*) from pg_extension where extname='uuid-ossp';
select 'has_ids', count(*) from pg_class where relname='ids';
select 'has_ah',  count(*) from pg_class where relname='ah';
select 'has_eca', count(*) from pg_class where relname='eca';
