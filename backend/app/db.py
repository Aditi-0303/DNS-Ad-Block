from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite:///./dns_analytics.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    from app import models

    Base.metadata.create_all(bind=engine)
    # `create_all` does not update an existing SQLite table.  Keep the local
    # demo database compatible when this project is upgraded in place.
    expected_columns = {
        "is_blocked": "BOOLEAN NOT NULL DEFAULT 0",
        "category": "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        "block_reason": "TEXT NOT NULL DEFAULT 'No matching Pi-hole rule reported'",
        "matched_rule": "VARCHAR(255)",
        "list_source": "VARCHAR(255)",
        "evidence": "TEXT NOT NULL DEFAULT '[]'",
        "false_positive_score": "FLOAT NOT NULL DEFAULT 0.0",
        "false_positive_risk": "VARCHAR(16) NOT NULL DEFAULT 'low'",
        "impact_summary": "TEXT NOT NULL DEFAULT ''",
        "request_count": "INTEGER NOT NULL DEFAULT 1",
    }
    inspector = inspect(engine)
    existing = {column["name"] for column in inspector.get_columns("dns_logs")}
    with engine.begin() as connection:
        for name, definition in expected_columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE dns_logs ADD COLUMN {name} {definition}"))
