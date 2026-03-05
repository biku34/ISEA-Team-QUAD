"""
Database configuration and session management for forensic recovery system.
Provides SQLAlchemy engine, session factory, and base model.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from typing import Generator
import yaml
from pathlib import Path

# Load configuration
config_path = Path(__file__).parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    config = yaml.safe_load(f)

# Database URL from config
DATABASE_URL = config['database']['url']

# Create engine with appropriate settings
if DATABASE_URL.startswith('sqlite'):
    # SQLite-specific settings
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=config['database'].get('echo', False)
    )
else:
    # For other databases (PostgreSQL, MySQL, etc.)
    engine = create_engine(
        DATABASE_URL,
        pool_size=config['database'].get('pool_size', 10),
        max_overflow=config['database'].get('max_overflow', 20),
        echo=config['database'].get('echo', False)
    )

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Database session dependency for FastAPI.
    Yields a database session and ensures it's closed after use.
    
    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database():
    """
    Initialize database by creating all tables.
    Should be called during application startup.
    """
    import app.models.evidence
    import app.models.partition
    import app.models.deleted_file
    import app.models.recovered_file
    import app.models.carved_file
    import app.models.carving_session
    import app.models.audit_log
    
    Base.metadata.create_all(bind=engine)
    print("✓ Database initialized successfully")


def drop_all_tables():
    """
    Drop all tables. USE WITH CAUTION!
    Only for development/testing purposes.
    """
    Base.metadata.drop_all(bind=engine)
    print("✓ All tables dropped")
