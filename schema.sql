-- readings: one row per MQTT message from any sensor node.
-- Type-specific columns are NULL for sensors that don't report them.
-- The full original payload is kept in `payload` so schema changes never lose data.
-- Needs MySQL 5.7+ / MariaDB 10.2+ (JSON column).

CREATE TABLE IF NOT EXISTS readings (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  node_id       VARCHAR(32)  NOT NULL,
  sensor        VARCHAR(16)  NOT NULL,
  topic         VARCHAR(128) NOT NULL,
  ts            DATETIME     NOT NULL COMMENT 'device timestamp, UTC',
  received_at   DATETIME(3)  NOT NULL COMMENT 'collector receive time, UTC',
  level_cm      FLOAT        NULL,
  level_pct     FLOAT        NULL,
  leak          TINYINT(1)   NULL,
  motion        TINYINT(1)   NULL,
  temperature_c FLOAT        NULL,
  humidity_pct  FLOAT        NULL,
  payload       JSON         NOT NULL,
  PRIMARY KEY (id),
  KEY idx_node_ts (node_id, ts),
  KEY idx_sensor_ts (sensor, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- audit_log: every rate-limit/plausibility decision, not just accepted readings.
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  node_id     VARCHAR(32)  NOT NULL,
  sensor      VARCHAR(16)  NOT NULL,
  decision    VARCHAR(20)  NOT NULL COMMENT 'accepted | flagged | rejected | rate_limited',
  reason      VARCHAR(255) NOT NULL,
  ts          DATETIME(3)  NOT NULL,
  PRIMARY KEY (id),
  KEY idx_node_ts (node_id, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- device_risk: one row per device, holding its current risk rating.
-- Upsert on each scan (INSERT ... ON DUPLICATE KEY UPDATE).
CREATE TABLE IF NOT EXISTS device_risk (
  node_id       VARCHAR(32)  NOT NULL,
  score         FLOAT        NOT NULL COMMENT 'overall risk score',
  severity      VARCHAR(16)  NOT NULL COMMENT 'LOW | MEDIUM | HIGH | CRITICAL (same values as Finding.severity)',
  last_scanned  DATETIME     NOT NULL COMMENT 'time of last scan, UTC',
  PRIMARY KEY (node_id),
  KEY idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
