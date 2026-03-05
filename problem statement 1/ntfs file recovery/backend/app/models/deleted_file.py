"""
DeletedFile model for tracking deleted files discovered via SleuthKit fls.
Stores MFT metadata and MACB timestamps for forensic timeline reconstruction.
"""

from sqlalchemy import Column, Integer, String, DateTime, BigInteger, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class DeletedFile(Base):
    """
    Represents a deleted file detected in NTFS partition.
    
    Forensic Requirements:
    - Stores MFT (Master File Table) metadata
    - MACB timestamps (Modified, Accessed, Changed, Birth)
    - Inode number for file recovery via icat
    - File status flags (deleted, unallocated, reallocated)
    - Links to partition and evidence for chain of custody
    """
    __tablename__ = "deleted_files"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Foreign Key to Partition
    partition_id = Column(Integer, ForeignKey("partitions.id", ondelete="CASCADE"),
                         nullable=False, index=True,
                         comment="Reference to parent partition")
    
    # File Identification
    inode = Column(BigInteger, nullable=False, index=True,
                  comment="NTFS MFT entry number (inode) - used for icat recovery")
    filename = Column(String(512), nullable=False, index=True,
                     comment="Original filename (may be partial if deleted)")
    file_path = Column(String(2048), nullable=True,
                      comment="Full path if reconstructable")
    
    # File Attributes
    size_bytes = Column(BigInteger, nullable=False,
                       comment="File size in bytes")
    file_type = Column(String(50), nullable=True, index=True,
                      comment="File type/extension (e.g., .docx, .jpg)")
    
    # Deletion Status
    is_deleted = Column(Boolean, default=True,
                       comment="Whether file is marked as deleted in MFT")
    is_recoverable = Column(Boolean, default=True,
                           comment="Whether file data is likely intact")
    is_reallocated = Column(Boolean, default=False,
                           comment="Whether file space has been reallocated")
    
    # MFT Entry Information
    mft_entry = Column(Integer, nullable=False,
                      comment="MFT entry number")
    mft_sequence = Column(Integer, nullable=True,
                         comment="MFT sequence number")
    mft_flags = Column(String(100), nullable=True,
                      comment="MFT flags (r/r = deleted and recoverable)")
    
    # MACB Timestamps (Forensic Timeline)
    time_modified = Column(DateTime, nullable=True, index=True,
                          comment="Modified time (M in MACB)")
    time_accessed = Column(DateTime, nullable=True, index=True,
                          comment="Accessed time (A in MACB)")
    time_changed = Column(DateTime, nullable=True, index=True,
                         comment="MFT Changed time (C in MACB)")
    time_birth = Column(DateTime, nullable=True, index=True,
                       comment="Creation/Birth time (B in MACB)")
    time_deleted = Column(DateTime, nullable=True, index=True,
                         comment="Estimated deletion time (if available)")
    
    # File Content Analysis
    content_hash = Column(String(64), nullable=True,
                         comment="SHA-256 hash if file data still exists")
    magic_bytes = Column(String(100), nullable=True,
                        comment="First few bytes for file type verification")
    
    # Recovery Status
    recovery_status = Column(String(50), default="not_attempted",
                            comment="Status: not_attempted, in_progress, recovered, failed")
    recovery_attempted_at = Column(DateTime, nullable=True,
                                  comment="When recovery was attempted")
    
    # Error Tracking
    recovery_error = Column(Text, nullable=True,
                           comment="Error message if recovery failed")
    
    # Forensic Metadata
    notes = Column(Text, nullable=True,
                  comment="Examiner notes about this file")
    flagged_for_review = Column(Boolean, default=False,
                               comment="Whether file is flagged for examiner review")
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False,
                          comment="When file was discovered via fls")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    partition = relationship("Partition", back_populates="deleted_files")
    recovered_file = relationship("RecoveredFile", back_populates="deleted_file", 
                                 uselist=False, cascade="all, delete-orphan")
    
    def __repr__(self):
        return (f"<DeletedFile(id={self.id}, inode={self.inode}, "
                f"filename={self.filename}, size={self.size_bytes})>")
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': self.id,
            'partition_id': self.partition_id,
            'inode': self.inode,
            'filename': self.filename,
            'file_path': self.file_path,
            'size_bytes': self.size_bytes,
            'file_type': self.file_type,
            'is_deleted': self.is_deleted,
            'is_recoverable': self.is_recoverable,
            'is_reallocated': self.is_reallocated,
            'mft_entry': self.mft_entry,
            'mft_sequence': self.mft_sequence,
            'mft_flags': self.mft_flags,
            'time_modified': self.time_modified.isoformat() if self.time_modified else None,
            'time_accessed': self.time_accessed.isoformat() if self.time_accessed else None,
            'time_changed': self.time_changed.isoformat() if self.time_changed else None,
            'time_birth': self.time_birth.isoformat() if self.time_birth else None,
            'time_deleted': self.time_deleted.isoformat() if self.time_deleted else None,
            'recovery_status': self.recovery_status,
            'recovery_attempted_at': self.recovery_attempted_at.isoformat() if self.recovery_attempted_at else None,
            'flagged_for_review': self.flagged_for_review,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }
    
    def timeline_dict(self):
        """Generate timeline entry for MACB timeline reconstruction"""
        events = []
        
        if self.time_modified:
            events.append({
                'timestamp': self.time_modified.isoformat(),
                'type': 'M',
                'description': f"Modified: {self.filename}",
                'inode': self.inode
            })
        
        if self.time_accessed:
            events.append({
                'timestamp': self.time_accessed.isoformat(),
                'type': 'A',
                'description': f"Accessed: {self.filename}",
                'inode': self.inode
            })
        
        if self.time_changed:
            events.append({
                'timestamp': self.time_changed.isoformat(),
                'type': 'C',
                'description': f"MFT Changed: {self.filename}",
                'inode': self.inode
            })
        
        if self.time_birth:
            events.append({
                'timestamp': self.time_birth.isoformat(),
                'type': 'B',
                'description': f"Created: {self.filename}",
                'inode': self.inode
            })
        
        return events
