package sqlstore

func init() {
	migrationDumps[25] = `
		PRAGMA foreign_keys=OFF;
		BEGIN TRANSACTION;
		CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
		CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
		CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime,"can_reattest" bool,"agent_version" varchar(255) );
		CREATE TABLE IF NOT EXISTS "attested_node_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255) );
		CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"admin" bool,"downstream" bool,"expiry" bigint,"revision_number" bigint,"store_svid" bool,"hint" varchar(255),"jwt_svid_ttl" integer,"additional_attributes" blob );
		CREATE TABLE IF NOT EXISTS "registered_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255) );
		CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
		CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
		INSERT INTO migrations VALUES(1,'2026-06-09 00:00:00.000000+00:00','2026-06-09 00:00:00.000000+00:00',25,'1.14.2-dev-jwtshare');
		CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
		CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"bundle_endpoint_url" varchar(255),"bundle_endpoint_profile" varchar(255),"endpoint_spiffe_id" varchar(255),"implicit" bool );
		CREATE TABLE IF NOT EXISTS "ca_journals" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"data" blob,"active_x509_authority_id" varchar(255),"active_jwt_authority_id" varchar(255) );
		CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
		CREATE INDEX idx_attested_node_entries_expires_at ON "attested_node_entries"(expires_at) ;
		CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
		CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
		CREATE INDEX idx_registered_entries_hint ON "registered_entries"("hint") ;
		CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
		CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
		CREATE INDEX idx_registered_entries_expiry ON "registered_entries"("expiry") ;
		CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
		CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
		CREATE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
		CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
		CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
		CREATE UNIQUE INDEX uix_federated_trust_domains_trust_domain ON "federated_trust_domains"(trust_domain) ;
		CREATE INDEX idx_ca_journals_active_x509_authority_id ON "ca_journals"(active_x509_authority_id) ;
		CREATE INDEX idx_ca_journals_active_jwt_authority_id ON "ca_journals"(active_jwt_authority_id) ;
		CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
		COMMIT;
	`
}
