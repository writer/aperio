CREATE TABLE "api_tokens" (
  "id" TEXT NOT NULL,
  "organization_id" TEXT NOT NULL,
  "created_by_user_id" TEXT NOT NULL,
  "name" VARCHAR(160) NOT NULL,
  "token_hash" VARCHAR(128) NOT NULL,
  "token_prefix" VARCHAR(32) NOT NULL,
  "scopes" TEXT[] NOT NULL DEFAULT ARRAY['READ']::TEXT[],
  "last_used_at" TIMESTAMP(3),
  "expires_at" TIMESTAMP(3),
  "revoked_at" TIMESTAMP(3),
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "api_tokens_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "api_tokens_token_hash_key" ON "api_tokens"("token_hash");
CREATE INDEX "api_tokens_organization_id_revoked_at_idx" ON "api_tokens"("organization_id", "revoked_at");
CREATE INDEX "api_tokens_organization_id_created_at_idx" ON "api_tokens"("organization_id", "created_at");

ALTER TABLE "api_tokens"
  ADD CONSTRAINT "api_tokens_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "api_tokens"
  ADD CONSTRAINT "api_tokens_created_by_user_id_fkey"
  FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
