-- Canonical cross-provider categorization for findings. Tags are an
-- additive classification (e.g. `auth.mfa_weakened`, `data.external_share`)
-- attached by the rule that emits the finding. They power cross-provider
-- grouping in the UI and feed compliance mappings without forcing the
-- detection layer onto a brittle canonical event schema.
--
-- See internal/ingestionworker/tags.go for the canonical taxonomy and
-- internal/ingestionworker/risk_score.go for the matching severity-band
-- scoring helper that landed in the same change.
ALTER TABLE "security_findings"
    ADD COLUMN "tags" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

-- GIN index supports the "filter findings by tag" path the UI will start
-- using next: WHERE 'auth.mfa_weakened' = ANY(tags) is rewritten by the
-- planner into an index scan over the GIN structure.
CREATE INDEX "security_findings_tags_idx"
    ON "security_findings" USING GIN ("tags");
