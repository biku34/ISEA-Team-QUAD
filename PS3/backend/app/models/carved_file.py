"""
CarvedFile model for files recovered via file carving (Scalpel).
These files are recovered from unallocated space without MFT metadata.
"""

from sqlalchemy import Column, Integer, String, DateTime, BigInteger, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class CarvedFile(Base):
    """
    Represents a file carved from unallocated space using Scalpel.
    
    Forensic Requirements:
    - Files recovered via signature-based carving
    - No MFT metadata available (files in unallocated space)
    - Links to partition where file was carved
    - Stores file offset in unallocated space
    - SHA-256 hash for integrity
    """
    __tablename__ = "carved_files"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Foreign Key to Partition
    partition_id = Column(Integer, ForeignKey("partitions.id", ondelete="CASCADE"),
                         nullable=False, index=True,
                         comment="Reference to partition where file was carved")
    
    # File Information
    carved_filename = Column(String(512), nullable=False,
                            comment="Generated filename (e.g., 00000000.jpg)")
    file_path = Column(String(2048), nullable=False, unique=True,
                      comment="Absolute path to carved file")
    size_bytes = Column(BigInteger, nullable=False,
                       comment="Carved file size in bytes")
    
    # Carving Information
    file_offset = Column(BigInteger, nullable=True,
                        comment="Byte offset in unallocated space where file was found")
    carving_method = Column(String(50), default="scalpel",
                           comment="Carving tool used (scalpel, photorec, etc.)")
    signature_type = Column(String(50), nullable=False, index=True,
                           comment="File signature matched (jpg, pdf, docx, etc.)")
    
    # File Type Analysis
    detected_type = Column(String(50), nullable=True,
                          comment="File type detected via magic bytes")
    mime_type = Column(String(100), nullable=True,
                      comment="MIME type")
    file_extension = Column(String(20), nullable=False,
                           comment="File extension from signature")
    
    # Integrity & Validation
    sha256_hash = Column(String(64), nullable=False, index=True,
                        comment="SHA-256 hash of carved file")
    md5_hash = Column(String(32), nullable=True,
                     comment="MD5 hash for legacy compatibility")
    
    header_valid = Column(Boolean, nullable=True,
                         comment="Whether file header is valid")
    footer_valid = Column(Boolean, nullable=True,
                         comment="Whether file footer/trailer is valid")
    is_complete = Column(Boolean, nullable=True,
                        comment="Whether file appears complete (not fragmented)")
    is_corrupted = Column(Boolean, default=False,
                         comment="Whether file appears corrupted")
    
    # Carving Session
    carving_session_id = Column(String(100), nullable=True,
                               comment="Batch ID for grouped carving operation")
    carved_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True,
                      comment="When file was carved")
    
    # File Content Analysis
    entropy = Column(String(20), nullable=True,
                    comment="File entropy (for detecting encryption/compression)")
    contains_text = Column(Boolean, nullable=True,
                          comment="Whether file contains readable text")
    
    # Export/Download Status
    is_exported = Column(Boolean, default=False,
                        comment="Whether file has been exported")
    export_count = Column(Integer, default=0,
                         comment="Number of downloads")
    last_exported_at = Column(DateTime, nullable=True,
                             comment="Last download time")
    
    # Review Status
    reviewed = Column(Boolean, default=False,
                     comment="Whether file has been reviewed by examiner")
    flagged_for_review = Column(Boolean, default=False,
                               comment="Flagged for additional review")
    is_relevant = Column(Boolean, nullable=True,
                        comment="Whether file is relevant to investigation")
    
    # Forensic Metadata
    notes = Column(Text, nullable=True,
                  comment="Examiner notes")
    evidence_tag = Column(String(100), nullable=True,
                         comment="Evidence tag/label")
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    partition = relationship("Partition", foreign_keys=[partition_id])
    
    def __repr__(self):
        return (f"<CarvedFile(id={self.id}, filename={self.carved_filename}, "
                f"type={self.signature_type}, size={self.size_bytes})>")
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': self.id,
            'partition_id': self.partition_id,
            'carved_filename': self.carved_filename,
            'file_path': self.file_path,
            'size_bytes': self.size_bytes,
            'file_offset': self.file_offset,
            'carving_method': self.carving_method,
            'signature_type': self.signature_type,
            'detected_type': self.detected_type,
            'mime_type': self.mime_type,
            'file_extension': self.file_extension,
            'sha256_hash': self.sha256_hash,
            'md5_hash': self.md5_hash,
            'header_valid': self.header_valid,
            'footer_valid': self.footer_valid,
            'is_complete': self.is_complete,
            'is_corrupted': self.is_corrupted,
            'carving_session_id': self.carving_session_id,
            'entropy': self.entropy,
            'contains_text': self.contains_text,
            'is_exported': self.is_exported,
            'export_count': self.export_count,
            'last_exported_at': self.last_exported_at.isoformat() if self.last_exported_at else None,
            'reviewed': self.reviewed,
            'flagged_for_review': self.flagged_for_review,
            'is_relevant': self.is_relevant,
            'carved_at': self.carved_at.isoformat() if self.carved_at else None
        }
