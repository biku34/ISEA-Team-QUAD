"""
CarvingSession model for tracking asynchronous file carving operations.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class CarvingSession(Base):
    """
    Represents an asynchronous carving operation session.
    
    Status transitions:
    - queued: Session created, background task not yet started
    - in_progress: Scalpel is currently scanning the image
    - completed: Carving finished successfully
    - failed: An error occurred during carving
    """
    __tablename__ = "carving_sessions"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    partition_id = Column(Integer, ForeignKey("partitions.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(String(100), unique=True, index=True, nullable=False)
    
    status = Column(String(20), default="queued", index=True) # queued, in_progress, completed, failed
    progress_message = Column(String(256), nullable=True)
    progress_percentage = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    
    # Results metadata
    files_carved_count = Column(Integer, default=0)
    total_bytes_carved = Column(Integer, default=0)
    
    # Timestamps
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    evidence = relationship("Evidence")
    partition = relationship("Partition")
    
    def to_dict(self):
        return {
            "id": self.id,
            "evidence_id": self.evidence_id,
            "partition_id": self.partition_id,
            "session_id": self.session_id,
            "status": self.status,
            "progress_message": self.progress_message,
            "progress_percentage": self.progress_percentage,
            "error_message": self.error_message,
            "files_carved_count": self.files_carved_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat()
        }
