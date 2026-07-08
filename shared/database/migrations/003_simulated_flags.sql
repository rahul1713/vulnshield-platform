-- Mark simulated engine output (web scanner stub, red team static fallback).
ALTER TABLE red_team_campaigns
    ADD COLUMN IF NOT EXISTS findings_simulated BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE red_team_findings
    ADD COLUMN IF NOT EXISTS is_simulated BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE web_scan_findings
    ADD COLUMN IF NOT EXISTS is_simulated BOOLEAN NOT NULL DEFAULT FALSE;
