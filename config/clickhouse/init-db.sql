-- Network Monitoring - ClickHouse Schema
-- Phase 1: Flow data from GoFlow2 via Vector
-- Phase 2: Zeek metadata, UniFi device/client tracking, correlated events

CREATE DATABASE IF NOT EXISTS netmon;

-- ==========================================================
-- NetFlow/IPFIX/sFlow records
-- Ingested via Vector HTTP sink from GoFlow2 JSON output
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.flows (
    time_received DateTime DEFAULT now(),
    src_addr String,
    dst_addr String,
    src_port UInt16 DEFAULT 0,
    dst_port UInt16 DEFAULT 0,
    proto UInt8 DEFAULT 0,
    bytes UInt64 DEFAULT 0,
    packets UInt64 DEFAULT 0,
    src_as UInt32 DEFAULT 0,
    dst_as UInt32 DEFAULT 0,
    in_if UInt32 DEFAULT 0,
    out_if UInt32 DEFAULT 0,
    etype UInt16 DEFAULT 0,
    tcp_flags UInt8 DEFAULT 0,
    ip_tos UInt8 DEFAULT 0,
    sampling_rate UInt64 DEFAULT 0,
    flow_type String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(time_received)
ORDER BY (time_received, src_addr, dst_addr)
TTL time_received + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ==========================================================
-- Materialized view: 5-minute flow aggregates
-- Provides fast top-talkers and bandwidth trending queries
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.flows_5m (
    timeslot DateTime,
    src_addr String,
    dst_addr String,
    proto UInt8,
    dst_port UInt16,
    total_bytes UInt64,
    total_packets UInt64,
    flow_count UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(timeslot)
ORDER BY (timeslot, src_addr, dst_addr, proto, dst_port)
TTL timeslot + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netmon.flows_5m_mv
TO netmon.flows_5m AS
SELECT
    toStartOfFiveMinutes(time_received) AS timeslot,
    src_addr,
    dst_addr,
    proto,
    dst_port,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    count() AS flow_count
FROM netmon.flows
GROUP BY timeslot, src_addr, dst_addr, proto, dst_port;

-- ==========================================================
-- Hourly aggregates for long-term trending
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.flows_hourly (
    timeslot DateTime,
    src_addr String,
    dst_addr String,
    proto UInt8,
    total_bytes UInt64,
    total_packets UInt64,
    flow_count UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(timeslot)
ORDER BY (timeslot, src_addr, dst_addr, proto)
TTL timeslot + INTERVAL 730 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netmon.flows_hourly_mv
TO netmon.flows_hourly AS
SELECT
    toStartOfHour(time_received) AS timeslot,
    src_addr,
    dst_addr,
    proto,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    count() AS flow_count
FROM netmon.flows
GROUP BY timeslot, src_addr, dst_addr, proto;

-- ==========================================================
-- Phase 2: Zeek connection logs
-- Ingested via Vector from Zeek JSON output
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.zeek_conn (
    ts DateTime64(6) DEFAULT now64(6),
    uid String DEFAULT '',
    src_addr String,
    src_port UInt16 DEFAULT 0,
    dst_addr String,
    dst_port UInt16 DEFAULT 0,
    proto String DEFAULT '',
    service String DEFAULT '',
    duration Float64 DEFAULT 0,
    orig_bytes Int64 DEFAULT 0,
    resp_bytes Int64 DEFAULT 0,
    conn_state String DEFAULT '',
    missed_bytes Int64 DEFAULT 0,
    history String DEFAULT '',
    orig_pkts UInt64 DEFAULT 0,
    resp_pkts UInt64 DEFAULT 0
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, src_addr, dst_addr)
TTL toDateTime(ts) + INTERVAL 60 DAY
SETTINGS index_granularity = 8192;

-- ==========================================================
-- Zeek DNS logs - critical for connectivity diagnostics
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.zeek_dns (
    ts DateTime64(6) DEFAULT now64(6),
    uid String DEFAULT '',
    src_addr String,
    src_port UInt16 DEFAULT 0,
    dst_addr String,
    dst_port UInt16 DEFAULT 0,
    proto String DEFAULT '',
    query String DEFAULT '',
    qclass_name String DEFAULT '',
    qtype_name String DEFAULT '',
    rcode_name String DEFAULT '',
    answers String DEFAULT '',
    ttl String DEFAULT '',
    rejected UInt8 DEFAULT 0
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, src_addr, query)
TTL toDateTime(ts) + INTERVAL 60 DAY
SETTINGS index_granularity = 8192;

-- ==========================================================
-- UniFi device inventory (from API poller)
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.unifi_devices (
    timestamp DateTime DEFAULT now(),
    mac String,
    ip String,
    name String,
    model String,
    type String,
    version String,
    uptime UInt64 DEFAULT 0,
    state UInt8 DEFAULT 0,
    cpu_usage Float64 DEFAULT 0,
    mem_usage Float64 DEFAULT 0,
    tx_bytes UInt64 DEFAULT 0,
    rx_bytes UInt64 DEFAULT 0,
    num_clients UInt32 DEFAULT 0
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, mac)
TTL timestamp + INTERVAL 90 DAY;

-- ==========================================================
-- UniFi client tracking (from API poller)
-- Key for enrichment: maps IP/MAC to device names
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.unifi_clients (
    timestamp DateTime DEFAULT now(),
    mac String,
    ip String,
    hostname String DEFAULT '',
    name String DEFAULT '',
    network String DEFAULT '',
    is_wired UInt8 DEFAULT 0,
    signal Int16 DEFAULT 0,
    channel UInt16 DEFAULT 0,
    radio String DEFAULT '',
    experience UInt8 DEFAULT 0,
    tx_bytes UInt64 DEFAULT 0,
    rx_bytes UInt64 DEFAULT 0,
    tx_rate UInt32 DEFAULT 0,
    rx_rate UInt32 DEFAULT 0,
    uptime UInt64 DEFAULT 0,
    ap_mac String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, mac)
TTL timestamp + INTERVAL 90 DAY;

-- ==========================================================
-- Correlated events (from analyzer correlation engine)
-- ==========================================================
CREATE TABLE IF NOT EXISTS netmon.correlated_events (
    timestamp DateTime DEFAULT now(),
    rule_name String,
    severity UInt8 DEFAULT 0,
    description String DEFAULT '',
    source_ips String DEFAULT '',
    details String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, rule_name, severity)
TTL timestamp + INTERVAL 180 DAY;
