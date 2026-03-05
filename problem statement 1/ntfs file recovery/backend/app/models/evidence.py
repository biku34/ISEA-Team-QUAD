"""
Evidence model for tracking uploaded forensic disk images.
Maintains chain of custody and hash verification data.
"""

from sqlalchemy import Column, Integer, String, DateTime, BigInteger, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Evidence(Base):
    """
    Represents a forensic disk image (E01/E02/E03 etc.)
    
    Forensic Requirements:
    - Immutable once uploaded (read-only)
    - SHA-256 hash for integrity verification
    - Chain of custody tracking (examiner, case info)
    - Upload timestamp for timeline reconstruction
    """
    __tablename__ = "evidence"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # File Information
    filename = Column(String(512), nullable=False, index=True, 
                     comment="Original E01 filename (case-sensitive)")
    file_path = Column(String(1024), nullable=False, unique=True,
                      comment="Absolute path to stored evidence file")
    size_bytes = Column(BigInteger, nullable=False,
                       comment="File size in bytes (uncompressed if E01)")
    
    # Forensic Hash Verification
    sha256_hash = Column(String(64), nullable=False, index=True,
                        comment="SHA-256 hash for integrity verification")
    hash_verified = Column(Boolean, default=False,
                          comment="Whether hash has been verified against known good")
    expected_hash = Column(String(64), nullable=True,
                          comment="Expected hash if provided during acquisition")
    
    # Chain of Custody
    case_name = Column(String(256), nullable=False, index=True,
                      comment="Case identifier (e.g., CASE-2024-001)")
    case_number = Column(String(128), nullable=True, index=True,
                        comment="Official case number if applicable")
    examiner = Column(String(256), nullable=False,
                     comment="Digital forensics examiner name")
    organization = Column(String(256), nullable=True,
                        comment="Law enforcement agency or organization")
    
    # Upload Metadata
    upload_time = Column(DateTime, default=datetime.utcnow, nullable=False, index=True,
                        comment="UTC timestamp of evidence upload")
    upload_ip = Column(String(45), nullable=True,
                      comment="IP address of uploader (IPv4 or IPv6)")
    
    # Image Information
    is_segmented = Column(Boolean, default=False,
                         comment="Whether this is part of a segmented image set")
    segment_number = Column(Integer, nullable=True,
                           comment="Segment number if part of E01/E02/E03 series")
    total_segments = Column(Integer, nullable=True,
                           comment="Total number of segments in series")
    
    # Mount Status
    is_mounted = Column(Boolean, default=False,
                       comment="Whether image is currently mounted")
    mount_point = Column(String(512), nullable=True,
                        comment="Current mount point if mounted")
    last_mounted = Column(DateTime, nullable=True,
                         comment="Last time image was mounted")
    
    # Analysis Status
    analysis_status = Column(String(50), default="uploaded",
                            comment="Status: uploaded, verified, mounted, analyzed, completed")
    partition_scan_completed = Column(Boolean, default=False,
                                     comment="Whether partition scan has been run")
    deleted_scan_completed = Column(Boolean, default=False,
                                   comment="Whether deleted file scan has been run")
    
    # Notes and Description
    description = Column(Text, nullable=True,
                        comment="Case description or notes about the evidence")
    notes = Column(Text, nullable=True,
                  comment="Additional forensic notes")
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    partitions = relationship("Partition", back_populates="evidence", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="evidence", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Evidence(id={self.id}, case={self.case_name}, file={self.filename})>"
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': self.id,
            'filename': self.filename,
            'size_bytes': self.size_bytes,
            'sha256_hash': self.sha256_hash,
            'hash_verified': self.hash_verified,
            'case_name': self.case_name,
            'case_number': self.case_number,
            'examiner': self.examiner,
            'organization': self.organization,
            'upload_time': self.upload_time.isoformat() if self.upload_time else None,
            'is_mounted': self.is_mounted,
            'mount_point': self.mount_point,
            'is_segmented': self.is_segmented,
            'segment_number': self.segment_number,
            'total_segments': self.total_segments,
            'analysis_status': self.analysis_status,
            'partition_scan_completed': self.partition_scan_completed,
            'deleted_scan_completed': self.deleted_scan_completed,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
