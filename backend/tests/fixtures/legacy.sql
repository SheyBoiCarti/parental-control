-- Reviewed schema from c53e818296d227aed45c26764af78b1cdbb2b10e; keep fixed when models change.

CREATE TABLE app_signatures (
	id INTEGER NOT NULL,
	app_name VARCHAR(100) NOT NULL,
	display_name VARCHAR(100) NOT NULL,
	domains JSON NOT NULL,
	ip_ranges JSON,
	is_builtin BOOLEAN,
	PRIMARY KEY (id),
	UNIQUE (app_name)
);

CREATE TABLE devices (
	id INTEGER NOT NULL,
	mac_address VARCHAR(17) NOT NULL,
	ip_address VARCHAR(15),
	hostname VARCHAR(255),
	vendor VARCHAR(255),
	friendly_name VARCHAR(255),
	is_monitored BOOLEAN,
	is_blocked BOOLEAN,
	first_seen DATETIME,
	last_seen DATETIME,
	is_online BOOLEAN,
	PRIMARY KEY (id)
);

CREATE TABLE settings (
	"key" VARCHAR(100) NOT NULL,
	value TEXT,
	updated_at DATETIME,
	PRIMARY KEY ("key")
);

CREATE TABLE access_logs (
	id INTEGER NOT NULL,
	device_id INTEGER NOT NULL,
	timestamp DATETIME,
	domain VARCHAR(255) NOT NULL,
	action VARCHAR(20) NOT NULL,
	app_name VARCHAR(100),
	PRIMARY KEY (id),
	FOREIGN KEY(device_id) REFERENCES devices (id) ON DELETE CASCADE
);

CREATE TABLE bandwidth_logs (
	id INTEGER NOT NULL,
	device_id INTEGER NOT NULL,
	timestamp DATETIME,
	bytes_sent INTEGER,
	bytes_received INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(device_id) REFERENCES devices (id) ON DELETE CASCADE
);

CREATE TABLE device_rules (
	id INTEGER NOT NULL,
	device_id INTEGER NOT NULL,
	rule_type VARCHAR(50) NOT NULL,
	rule_value JSON NOT NULL,
	is_active BOOLEAN,
	created_at DATETIME,
	updated_at DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(device_id) REFERENCES devices (id) ON DELETE CASCADE
);
