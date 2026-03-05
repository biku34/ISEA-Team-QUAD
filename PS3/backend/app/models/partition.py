"""
Partition model for tracking detected partitions in forensic images.
Stores partition table data extracted via mmls (SleuthKit).
"""

from sqlalchemy import Column, Integer, String, DateTime, BigInteger, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Partition(Base):
    """
    Represents a partition detected in a forensic disk image.
    
    Forensic Requirements:
    - Stores partition table metadata (offset, size, type)
    - Links to parent evidence for chain of custody
    - Tracks filesystem type (NTFS focus for this system)
    - Maintains analysis status for deleted file scanning
    """
    __tablename__ = "partitions"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Foreign Key to Evidence
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), 
                        nullable=False, index=True,
                        comment="Reference to parent evidence image")
    
    # Partition Information (from mmls output)
    partition_number = Column(Integer, nullable=False,
                             comment="Partition index (0-based or 1-based per mmls)")
    slot = Column(Integer, nullable=True,
                 comment="Partition slot number from partition table")
    start_offset = Column(BigInteger, nullable=False,
                         comment="Starting sector offset")
    end_offset = Column(BigInteger, nullable=True,
                       comment="Ending sector offset")
    length_sectors = Column(BigInteger, nullable=False,
                           comment="Length in sectors")
    size_bytes = Column(BigInteger, nullable=False,
                       comment="Size in bytes (length * sector_size)")
    
    # Filesystem Information
    filesystem_type = Column(String(50), nullable=False, index=True,
                            comment="Filesystem type (NTFS, FAT32, ext4, etc.)")
    description = Column(String(512), nullable=True,
                        comment="Partition description from mmls")
    
    # NTFS-Specific Information
    is_ntfs = Column(Integer, default=0,
                    comment="1 if NTFS, 0 otherwise (for quick filtering)")
    ntfs_volume_name = Column(String(256), nullable=True,
                             comment="NTFS volume label if available")
    
    # Analysis Status
    scan_status = Column(String(50), default="detected",
                        comment="Status: detected, scanning, completed, error")
    deleted_file_count = Column(Integer, default=0,
                               comment="Number of deleted files found")
    last_scan_time = Column(DateTime, nullable=True,
                           comment="Last time deleted files were scanned")
    
    # Mount Information
    is_mounted = Column(Integer, default=0,
                       comment="Whether partition is currently mounted (via fls)")
    
    # Error Tracking
    scan_error = Column(Text, nullable=True,
                       comment="Error message if scan failed")
    
    # Metadata
    notes = Column(Text, nullable=True,
                  comment="Additional forensic notes about partition")
    
    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False,
                        comment="When partition was detected via mmls")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    evidence = relationship("Evidence", back_populates="partitions")
    deleted_files = relationship("DeletedFile", back_populates="partition", cascade="all, delete-orphan")
    
    def __repr__(self):
        return (f"<Partition(id={self.id}, evidence_id={self.evidence_id}, "
                f"num={self.partition_number}, fs={self.filesystem_type})>")
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': self.id,
            'evidence_id': self.evidence_id,
            'partition_number': self.partition_number,
            'slot': self.slot,
            'start_offset': self.start_offset,
            'end_offset': self.end_offset,
            'length_sectors': self.length_sectors,
            'size_bytes': self.size_bytes,
            'filesystem_type': self.filesystem_type,
            'description': self.description,
            'is_ntfs': bool(self.is_ntfs),
            'ntfs_volume_name': self.ntfs_volume_name,
            'scan_status': self.scan_status,
            'deleted_file_count': self.deleted_file_count,
            'last_scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
            'is_mounted': bool(self.is_mounted),
            'scan_error': self.scan_error,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None
        }
