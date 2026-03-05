"""
NTFSArtifact model — stores metadata for extracted NTFS system files.

Phase 1 of the wipe detection pipeline stores one record per extracted
artifact ($MFT, $Bitmap, $UsnJrnl:$J, $LogFile, $AttrDef, $Boot).
"""

from sqlalchemy import (
    Column, Integer, String, DateTime, BigInteger,
    ForeignKey, Text, Index
)
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class NTFSArtifact(Base):
    """
    Records metadata for each NTFS system file extracted from an evidence image.

    One row is created per artifact per extraction run. Re-extraction creates
    new rows (old rows are NOT overwritten) to maintain audit integrity.
    """

    __tablename__ = "ntfs_artifacts"

    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # Foreign keys
    evidence_id = Column(
        Integer,
        ForeignKey("evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Parent evidence image"
    )
    partition_id = Column(
        Integer,
        ForeignKey("partitions.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Partition the artifact was extracted from"
    )

    # Artifact identity
    artifact_name = Column(
        String(64),
        nullable=False,
        comment="e.g. $MFT, $Bitmap, $UsnJrnl:$J"
    )
    inode = Column(
        String(32),
        nullable=True,
        comment="MFT inode used by icat (e.g. '0', '6', '11-128-4')"
    )

    # Storage
    file_path = Column(
        Text,
        nullable=True,
        comment="Absolute path to extracted artifact on disk"
    )
    size_bytes = Column(
        BigInteger,
        default=0,
        nullable=False,
        comment="Size of extracted artifact in bytes"
    )

    # Integrity
    sha256_hash = Column(
        String(64),
        nullable=True,
        comment="SHA-256 hash of the extracted file (chain of custody)"
    )

    # Status & timing
    extracted_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
        comment="UTC timestamp of extraction"
    )
    extraction_status = Column(
        String(32),
        default="not_attempted",
        nullable=False,
        index=True,
        comment="not_attempted | success | failed"
    )
    error_message = Column(
        Text,
        nullable=True,
        comment="Error detail if extraction_status == failed"
    )

    # Relationships
    evidence = relationship("Evidence", back_populates="ntfs_artifacts")

    # Indexes for common queries
    __table_args__ = (
        Index("idx_ntfs_artifact_evidence_name", "evidence_id", "artifact_name"),
        Index("idx_ntfs_artifact_status",        "extraction_status"),
    )

    def __repr__(self) -> str:
        return (
            f"<NTFSArtifact(id={self.id}, evidence_id={self.evidence_id}, "
            f"artifact={self.artifact_name}, status={self.extraction_status})>"
        )

    def to_dict(self) -> dict:
        """Serialise to dict for API responses."""
        return {
            "id":                self.id,
            "evidence_id":       self.evidence_id,
            "partition_id":      self.partition_id,
            "artifact_name":     self.artifact_name,
            "inode":             self.inode,
            "file_path":         self.file_path,
            "size_bytes":        self.size_bytes,
            "sha256_hash":       self.sha256_hash,
            "extracted_at":      self.extracted_at.isoformat() if self.extracted_at else None,
            "extraction_status": self.extraction_status,
            "error_message":     self.error_message,
        }
