PRAGMA foreign_keys = ON;

CREATE TABLE products (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE releases (
  id INTEGER PRIMARY KEY,
  product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(product_id, version)
);
CREATE TABLE components (
  id INTEGER PRIMARY KEY,
  release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  purl TEXT NOT NULL DEFAULT '',
  UNIQUE(release_id, ecosystem, name, version)
);
CREATE INDEX components_release_id_idx ON components(release_id);

CREATE TABLE sbom_imports (
  id INTEGER PRIMARY KEY,
  release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
  format TEXT NOT NULL,
  spec_version TEXT NOT NULL,
  serial_number TEXT NOT NULL DEFAULT '',
  document_sha256 TEXT NOT NULL,
  source_name TEXT NOT NULL DEFAULT '',
  components_discovered INTEGER NOT NULL,
  components_imported INTEGER NOT NULL,
  components_already_present INTEGER NOT NULL,
  components_skipped INTEGER NOT NULL,
  components_duplicated INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX sbom_imports_release_id_idx ON sbom_imports(release_id);

CREATE TABLE vulnerability_syncs (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  synchronized_at TEXT NOT NULL,
  package_count INTEGER NOT NULL,
  vulnerability_count INTEGER NOT NULL
);
CREATE TABLE package_snapshots (
  id INTEGER PRIMARY KEY,
  sync_id INTEGER NOT NULL REFERENCES vulnerability_syncs(id),
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  UNIQUE(ecosystem, name, version)
);
CREATE TABLE vulnerabilities (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  source_id TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '',
  published TEXT NOT NULL DEFAULT '',
  modified TEXT NOT NULL DEFAULT '',
  withdrawn TEXT NOT NULL DEFAULT '',
  aliases_json TEXT NOT NULL DEFAULT '[]',
  severity_json TEXT NOT NULL DEFAULT '[]',
  affected_json TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL,
  UNIQUE(source, source_id)
);
CREATE TABLE vulnerability_aliases (
  vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  alias TEXT NOT NULL,
  PRIMARY KEY(vulnerability_id, alias)
);
CREATE TABLE package_vulnerability_matches (
  package_snapshot_id INTEGER NOT NULL REFERENCES package_snapshots(id) ON DELETE CASCADE,
  vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  PRIMARY KEY(package_snapshot_id, vulnerability_id)
);
CREATE INDEX package_snapshots_sync_id_idx ON package_snapshots(sync_id);
CREATE INDEX vulnerability_aliases_alias_idx ON vulnerability_aliases(alias);
CREATE INDEX package_vulnerability_matches_vulnerability_idx ON package_vulnerability_matches(vulnerability_id);

CREATE TABLE finding_scans (
  id INTEGER PRIMARY KEY,
  release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
  data_source TEXT NOT NULL,
  synchronized_at TEXT NOT NULL DEFAULT '',
  scanned_at TEXT NOT NULL,
  component_count INTEGER NOT NULL,
  matched_count INTEGER NOT NULL,
  new_count INTEGER NOT NULL,
  existing_count INTEGER NOT NULL,
  reopened_count INTEGER NOT NULL,
  no_longer_matched_count INTEGER NOT NULL
);
CREATE TABLE findings (
  id INTEGER PRIMARY KEY,
  release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  component_name TEXT NOT NULL,
  component_version TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  aliases_json TEXT NOT NULL DEFAULT '[]',
  summary TEXT NOT NULL DEFAULT '',
  review_status TEXT NOT NULL DEFAULT 'needs-review',
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  no_longer_matched_at TEXT NOT NULL DEFAULT '',
  last_scan_id INTEGER NOT NULL REFERENCES finding_scans(id),
  UNIQUE(release_id, ecosystem, component_name, component_version, vulnerability_id)
);
CREATE INDEX finding_scans_release_id_idx ON finding_scans(release_id, scanned_at);
CREATE INDEX findings_release_active_idx ON findings(release_id, active);
CREATE INDEX findings_vulnerability_id_idx ON findings(vulnerability_id);

CREATE TABLE assessments (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('investigating', 'affected', 'not-affected', 'fixed')),
  reason TEXT NOT NULL DEFAULT '',
  reviewer TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  assessed_at TEXT NOT NULL
);
CREATE INDEX assessments_finding_time_idx ON assessments(finding_id, assessed_at, id);

CREATE TABLE kev_syncs (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  catalog_version TEXT NOT NULL,
  date_released TEXT NOT NULL,
  synchronized_at TEXT NOT NULL,
  entry_count INTEGER NOT NULL
);
CREATE TABLE kev_entries (
  cve_id TEXT PRIMARY KEY COLLATE NOCASE,
  sync_id INTEGER NOT NULL REFERENCES kev_syncs(id) ON DELETE CASCADE,
  vendor_project TEXT NOT NULL,
  product TEXT NOT NULL,
  vulnerability_name TEXT NOT NULL,
  date_added TEXT NOT NULL,
  short_description TEXT NOT NULL,
  required_action TEXT NOT NULL,
  due_date TEXT NOT NULL,
  known_ransomware_campaign_use TEXT NOT NULL DEFAULT '',
  forensic_triage TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  cwes_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX kev_entries_sync_id_idx ON kev_entries(sync_id);

CREATE TABLE feed_imports (
  id INTEGER PRIMARY KEY,
  format_version INTEGER NOT NULL,
  bundle_created_at TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  source_name TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  osv_synchronized_at TEXT NOT NULL,
  kev_synchronized_at TEXT NOT NULL,
  package_count INTEGER NOT NULL,
  vulnerability_count INTEGER NOT NULL,
  kev_entry_count INTEGER NOT NULL
);
CREATE INDEX feed_imports_imported_at_idx ON feed_imports(imported_at);

INSERT INTO products VALUES (1, 'AG-200', 'Industrial gateway', '2026-10-01T09:00:00Z');
INSERT INTO releases VALUES (1, 1, '2.2', '2026-10-01T09:01:00Z');
INSERT INTO components VALUES (1, 1, 'Alpine', 'openssl', '3.0.8', '2026-10-01T09:02:00Z', 'pkg:apk/alpine/openssl@3.0.8');
INSERT INTO sbom_imports VALUES (1, 1, 'CycloneDX JSON', '1.6', 'urn:uuid:v009-fixture', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'firmware-2.2.cdx.json', 1, 1, 0, 0, 0, '2026-10-01T09:02:00Z');

INSERT INTO vulnerability_syncs VALUES (1, 'OSV', '2026-10-01T10:00:00Z', 1, 1);
INSERT INTO package_snapshots VALUES (1, 1, 'Alpine', 'openssl', '3.0.8');
INSERT INTO vulnerabilities VALUES (1, 'OSV', 'OSV-2026-1', 'Fixture advisory', 'Fixture details', '2026-09-01T00:00:00Z', '2026-10-01T00:00:00Z', '', '["CVE-2026-12345"]', '[]', '[]', '2026-10-01T10:00:00Z');
INSERT INTO vulnerability_aliases VALUES (1, 'CVE-2026-12345');
INSERT INTO package_vulnerability_matches VALUES (1, 1);

INSERT INTO finding_scans VALUES (1, 1, 'local-osv-snapshot', '2026-10-01T10:00:00Z', '2026-10-01T10:05:00Z', 1, 1, 1, 0, 0, 0);
INSERT INTO findings VALUES (1, 1, 'Alpine', 'openssl', '3.0.8', 'OSV-2026-1', '["CVE-2026-12345"]', 'Fixture advisory', 'not-affected', 1, '2026-10-01T10:05:00Z', '2026-10-01T10:05:00Z', '', 1);
INSERT INTO assessments VALUES (1, 1, 'not-affected', 'Feature disabled', 'fixture-reviewer', 'SEC-009', '2026-10-01T10:10:00Z');

INSERT INTO kev_syncs VALUES (1, 'CISA KEV', '2026.10.01', '2026-10-01T00:00:00Z', '2026-10-01T10:00:00Z', 1);
INSERT INTO kev_entries VALUES ('CVE-2026-12345', 1, 'Example', 'OpenSSL', 'Fixture issue', '2026-09-15', 'Fixture description', 'Apply update', '2026-10-15', 'Unknown', '', '', '["CWE-787"]');

INSERT INTO feed_imports VALUES (1, 1, '2026-10-01T09:59:00Z', '2026-10-01T10:00:00Z', 'fixture.bundle', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '2026-10-01T10:00:00Z', '2026-10-01T10:00:00Z', 1, 1, 1);

PRAGMA user_version = 7;
