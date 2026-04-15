from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # UniFi Controller
    unifi_host: str = "https://192.168.1.1"
    unifi_username: str = "admin"
    unifi_password: str = "changeme"
    unifi_site: str = "default"
    unifi_verify_ssl: bool = False

    # ClickHouse
    clickhouse_host: str = "clickhouse"
    clickhouse_port: int = 9000
    clickhouse_user: str = "netmon"
    clickhouse_password: str = "changeme"
    clickhouse_db: str = "netmon"

    # Loki
    loki_url: str = "http://loki:3100"

    # Zeek
    zeek_log_dir: str = "/zeek-logs"

    # GeoIP (MaxMind GeoLite2 database path)
    geoip_db_path: str = "/app/data/GeoLite2-City.mmdb"

    # Polling intervals (seconds)
    unifi_poll_interval: int = 60
    correlation_interval: int = 300

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()
