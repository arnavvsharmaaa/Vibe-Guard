"""
Phase 9 persistence: SQLAlchemy 2.0 models for scans, findings and AI analyses.

Only generic column types are used so the schema also works on PostgreSQL. SQLite is the default
(`DATABASE_URL`); the database file lives next to this module, outside uploads/.
"""

import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import (JSON, DateTime, Engine, ForeignKey, Integer, String, Text, UniqueConstraint,
                        create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

DEFAULT_DATABASE_URL = f"sqlite:///{(Path(__file__).resolve().parent / 'vibe_guard.db').as_posix()}"


def database_url() -> str:
    return os.getenv("DATABASE_URL", "").strip() or DEFAULT_DATABASE_URL


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    project_name: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(16), index=True)
    filename: Mapped[str] = mapped_column(Text)
    file_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    security_score: Mapped[int | None] = mapped_column(Integer)
    scanners: Mapped[dict | None] = mapped_column(JSON)  # per-scanner summary, no raw output
    ai: Mapped[dict | None] = mapped_column(JSON)  # AI summary: status, provider, model, counts

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True, order_by="Finding.id")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id", name="uq_findings_scan_finding"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32), ForeignKey("scans.scan_id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(32))  # public per-scan ID, e.g. VG-001
    type: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    file: Mapped[str] = mapped_column(Text)  # POSIX path relative to the scan's source/ directory
    line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    code: Mapped[str | None] = mapped_column(Text)  # untrusted snippet, stored as text only
    scanner: Mapped[str] = mapped_column(String(16))
    rule: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    cwe: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(Text)
    scanners: Mapped[list] = mapped_column(JSON)
    related_rules: Mapped[list] = mapped_column(JSON)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    ai_analysis: Mapped["AIAnalysis | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True)


class AIAnalysis(Base):
    """Advisory AI output for one finding (1:1). It never affects findings or the score."""

    __tablename__ = "ai_analyses"

    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))  # completed | failed | timeout | invalid_output | skipped
    explanation: Mapped[str | None] = mapped_column(Text)
    detection_reason: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text)
    fixed_code: Mapped[str | None] = mapped_column(Text)  # untrusted AI text, never executed
    remediation_steps: Mapped[list | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)

    finding: Mapped[Finding] = relationship(back_populates="ai_analysis")


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_db_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        # Background scan tasks run in a thread pool; every operation uses its own short session.
        engine = create_engine(url, connect_args={"check_same_thread": False})
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        return engine
    return create_engine(url, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(engine: Engine) -> None:
    """Create missing tables. Safe to run on every start; existing data is kept."""
    Base.metadata.create_all(engine)
