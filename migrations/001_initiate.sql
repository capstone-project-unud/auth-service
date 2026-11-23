CREATE TABLE IF NOT EXISTS auth_service.credentials (
  user_id uuid PRIMARY KEY,
  password_hash text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_service.sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth_service.credentials(user_id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sessions_user_id ON auth_service.sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON auth_service.sessions(expires_at);
