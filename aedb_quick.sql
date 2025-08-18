select current_database();
select version();
select extname, count(*) from pg_extension
  where extname in ('pgcrypto','uuid-ossp')
  group by 1 order by 1;
