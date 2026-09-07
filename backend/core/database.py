"""
PROJECT MATHRA - Async Database and Threat Telemetry Store
Built with SQLAlchemy 2.0 Async Engine.
Default: SQLite (aiosqlite) with seamless switch to PostgreSQL (asyncpg) via DATABASE_URL.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, select, func, desc
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from backend.core.config import get_settings
from backend.core.logging import logger

Base = declarative_base()  # engine for database

class ThreatEvent(Base):   # this code is used to store all detected DLP, secret, guardrail and shadow AI incidents.
    """Stores all detected DLP, secret, guardrail and shadow AI incidents.""" 
    __tablename__ = "threat_events"  # table name for threat events

    id = Column(Integer, primary_key=True, autoincrement=True)  # primary key
    incident_id = Column(String(64), index=True, nullable=False)  # incident id
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)  # timestamp  
    user_id = Column(String(128), default="anonymous", nullable=False)  # user id
    source_ip = Column(String(64), default="127.0.0.1", nullable=False)
    event_type = Column(String(64), index=True, nullable=False)  # PII_REDACTED, SECRET_BLOCKED, PROMPT_INJECTION, SHADOW_AI
    severity = Column(String(32), default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    action_taken = Column(String(32), default="REDACTED", nullable=False)  # REDACTED, BLOCKED, ALERTED, PASSED
    details_sanitized = Column(Text, default="", nullable=False)  # JSON or descriptive text without raw secrets
    latency_ms = Column(Float, default=0.0, nullable=False) # 

class RedTeamRun(Base):    # this code is used to store all results of red team runs
    """Stores execution summaries of automated adversarial evaluations."""
    __tablename__ = "redteam_runs" # table name for red team runs

    id = Column(Integer, primary_key=True, autoincrement=True) # primary key
    run_id = Column(String(64), unique=True, index=True, nullable=False)  # run id
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)  # timestamp  
    total_tests = Column(Integer, default=0, nullable=False)  # total number of tests
    passed = Column(Integer, default=0, nullable=False)  # number of passed tests
    failed = Column(Integer, default=0, nullable=False)  # number of failed tests
    vulnerability_score = Column(Float, default=0.0, nullable=False) # vulnerability score
    report_path = Column(String(256), default="", nullable=False)  # path to report
    summary_json = Column(Text, default="", nullable=False)  # summary of the run

# Initialize async engine & session factory
settings = get_settings()

# Ensure directory exists if SQLite
if "sqlite" in settings.database_url:
    db_path = settings.database_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

# async engine and session factory
engine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True,
)

# async session local
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# initialize database
async def init_db() -> None:
    """Creates database tables if they do not already exist."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Project Mathra threat database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)

# Log threat event
async def log_threat_event(
    incident_id: str,
    event_type: str,
    severity: str,
    action_taken: str,
    details_sanitized: str,
    latency_ms: float = 0.0,
    user_id: str = "anonymous",
    source_ip: str = "127.0.0.1",
) -> None:
    """Asynchronously logs a security incident into the database."""
    try:
        async with AsyncSessionLocal() as session:
            event = ThreatEvent(
                incident_id=incident_id,
                event_type=event_type,
                severity=severity,
                action_taken=action_taken,
                details_sanitized=details_sanitized,
                latency_ms=latency_ms,
                user_id=user_id,
                source_ip=source_ip,
            )
            session.add(event)
            await session.commit()
    except Exception as e:
        logger.error(f"Failed to log threat event to database: {e}", exc_info=True)

# Get recent events
async def get_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches most recent threat events for the SOC dashboard."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(ThreatEvent).order_by(desc(ThreatEvent.timestamp)).limit(limit)
            result = await session.execute(stmt)
            events = result.scalars().all()
            return [
                {
                    "id": e.id,
                    "incident_id": e.incident_id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                    "user_id": e.user_id,
                    "source_ip": e.source_ip,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "action_taken": e.action_taken,
                    "details": e.details_sanitized,
                    "latency_ms": e.latency_ms,
                }
                for e in events
            ]
    except Exception as e:
        logger.error(f"Failed to query recent events: {e}", exc_info=True)
        return []

# Get threat metrics
async def get_threat_metrics() -> Dict[str, Any]:
    """Computes high-level aggregated metrics for SOC telemetry display."""
    try:
        async with AsyncSessionLocal() as session:
            total_count_res = await session.execute(select(func.count(ThreatEvent.id)))
            total_events = total_count_res.scalar() or 0

            # Count by event_type
            type_stmt = select(ThreatEvent.event_type, func.count(ThreatEvent.id)).group_by(ThreatEvent.event_type)
            type_res = await session.execute(type_stmt)
            by_type = {row[0]: row[1] for row in type_res.all()}

            # Count by action_taken
            action_stmt = select(ThreatEvent.action_taken, func.count(ThreatEvent.id)).group_by(ThreatEvent.action_taken)
            action_res = await session.execute(action_stmt)
            by_action = {row[0]: row[1] for row in action_res.all()}

            # Avg latency
            latency_res = await session.execute(select(func.avg(ThreatEvent.latency_ms)))
            avg_latency = latency_res.scalar() or 0.0

            return {
                "total_events": total_events,
                "by_type": by_type,
                "by_action": by_action,
                "avg_latency_ms": round(float(avg_latency), 2),
            }
    except Exception as e:
        logger.error(f"Failed to compute threat metrics: {e}", exc_info=True)
        return {
            "total_events": 0,
            "by_type": {},
            "by_action": {},
            "avg_latency_ms": 0.0,
        }