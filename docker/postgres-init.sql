-- Required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Optimization
ALTER SYSTEM SET shared_buffers = '512MB';
ALTER SYSTEM SET effective_cache_size = '2GB';
ALTER SYSTEM SET maintenance_work_mem = '128MB';
ALTER SYSTEM SET random_page_cost = 1.1;
