"""
RecoveredFile model for tracking successfully recovered deleted files.
Links recovered file data to original deleted file metadata.
"""

from sqlalchemy import Column, Integer, String, DateTime, BigInteger, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class RecoveredFile(Base):
    """
    Represents a successfully recovered deleted file.
    
    Forensic Requirements:
    - Links to original deleted file for provenance
    - Stores SHA-256 hash for integrity verification
    - Tracks recovery method (icat vs carving)
    - Maintains chain of custody timestamps
    - Provides download path for frontend access
    """
    __tablename__ = "recovered_files"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Foreign Key to DeletedFile
    deleted_file_id = Column(Integer, ForeignKey("deleted_files.id", ondelete="CASCADE"),
                            nullable=True, index=True,
                            comment="Reference to original deleted file (null for carved files)")
    
    # File Information
    original_filename = Column(String(512), nullable=False,
                              comment="Original filename from MFT")
    recovered_filename = Column(String(512), nullable=False, unique=True,
                               comment="Filename in recovered storage (timestamped)")
    file_path = Column(String(2048), nullable=False, unique=True,
                      comment="Absolute path to recovered file")
    size_bytes = Column(BigInteger, nullable=False,
                       comment="Recovered file size in bytes")
    
    # Integrity Verification
    sha256_hash = Column(String(64), nullable=False, index=True,
                        comment="SHA-256 hash of recovered file data")
    md5_hash = Column(String(32), nullable=True,
                     comment="MD5 hash for legacy compatibility")
    
    # Recovery Method
    recovery_method = Column(String(50), nullable=False,
                            comment="Method: icat, scalpel, manual")
    recovery_tool = Column(String(100), nullable=True,
                          comment="Specific tool used (icat, scalpel)")
    recovery_command = Column(Text, nullable=True,
                             comment="Exact command used for recovery (reproducibility)")
    
    # Recovery Status
    recovery_success = Column(Boolean, default=True,
                             comment="Whether recovery was fully successful")
    is_partial = Column(Boolean, default=False,
                       comment="Whether file was only partially recovered")
    corruption_detected = Column(Boolean, default=False,
                                comment="Whether file appears corrupted")
    
    # File Type Analysis
    file_type = Column(String(50), nullable=True, index=True,
                      comment="Detected file type (via magic bytes)")
    mime_type = Column(String(100), nullable=True,
                      comment="MIME type of recovered file")
    file_extension = Column(String(20), nullable=True,
                           comment="File extension")
    
    # Validation
    header_valid = Column(Boolean, nullable=True,
                         comment="Whether file header is valid")
    signature_valid = Column(Boolean, nullable=True,
                            comment="Whether file signature matches type")
    
    # Export/Download Status
    is_exported = Column(Boolean, default=False,
                        comment="Whether file has been exported/downloaded")
    export_count = Column(Integer, default=0,
                         comment="Number of times file has been downloaded")
    last_exported_at = Column(DateTime, nullable=True,
                             comment="Last download timestamp")
    
    # Forensic Metadata
    examiner_notes = Column(Text, nullable=True,
                           comment="Forensic examiner notes")
    evidence_tag = Column(String(100), nullable=True,
                         comment="Evidence tag/label for court")
    flagged_for_review = Column(Boolean, default=False,
                               comment="Flagged for additional review")
    
    # Timestamps
    recovered_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True,
                         comment="When file was recovered")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    deleted_file = relationship("DeletedFile", back_populates="recovered_file")
    
    def __repr__(self):
        return (f"<RecoveredFile(id={self.id}, filename={self.original_filename}, "
                f"size={self.size_bytes}, method={self.recovery_method})>")
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': self.id,
            'deleted_file_id': self.deleted_file_id,
            'original_filename': self.original_filename,
            'recovered_filename': self.recovered_filename,
            'file_path': self.file_path,
            'size_bytes': self.size_bytes,
            'sha256_hash': self.sha256_hash,
            'md5_hash': self.md5_hash,
            'recovery_method': self.recovery_method,
            'recovery_tool': self.recovery_tool,
            'recovery_success': self.recovery_success,
            'is_partial': self.is_partial,
            'corruption_detected': self.corruption_detected,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'file_extension': self.file_extension,
            'header_valid': self.header_valid,
            'signature_valid': self.signature_valid,
            'is_exported': self.is_exported,
            'export_count': self.export_count,
            'last_exported_at': self.last_exported_at.isoformat() if self.last_exported_at else None,
            'flagged_for_review': self.flagged_for_review,
            'recovered_at': self.recovered_at.isoformat() if self.recovered_at else None
        }
