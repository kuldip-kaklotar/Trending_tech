-- Customers-first schema. Safe to run repeatedly (all statements are idempotent).
CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','staff')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Customer IDs keep the existing C-1001 style so current purchase records still match.
CREATE SEQUENCE IF NOT EXISTS customer_code_seq START 1001;

CREATE TABLE IF NOT EXISTS customers (
  id            BIGSERIAL PRIMARY KEY,
  customer_code TEXT NOT NULL UNIQUE DEFAULT ('C-' || nextval('customer_code_seq')),
  name          TEXT NOT NULL,
  mobile        TEXT NOT NULL CHECK (mobile ~ '^[6-9][0-9]{9}$'),
  alt_mobile    TEXT NOT NULL DEFAULT '',
  email         TEXT NOT NULL DEFAULT '',
  address       TEXT NOT NULL DEFAULT '',
  city          TEXT NOT NULL DEFAULT '',
  state         TEXT NOT NULL DEFAULT '',
  pin           TEXT NOT NULL DEFAULT '',
  reg_no        TEXT NOT NULL,
  bike_brand    TEXT NOT NULL DEFAULT '',
  bike_model    TEXT NOT NULL DEFAULT '',
  chassis       TEXT NOT NULL DEFAULT '',
  archived      BOOLEAN NOT NULL DEFAULT false,
  archived_at   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- One active customer per bike registration number (prevents duplicates, also on import).
CREATE UNIQUE INDEX IF NOT EXISTS customers_reg_active_uq ON customers (reg_no) WHERE NOT archived;
CREATE INDEX IF NOT EXISTS customers_mobile_idx ON customers (mobile);
