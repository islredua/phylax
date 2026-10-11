-- Inicialización mínima de PostgreSQL
-- Django se encarga de las migraciones del esquema. Este archivo deja la base
-- limpia y agrega extensiones útiles.

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Las migraciones de Django crearán las tablas al correr `manage.py migrate`.
