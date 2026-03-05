"""
AuditLog model for complete chain of custody tracking.
Every operation on evidence must be logged for forensic integrity.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class AuditLog(Base):
    """
    Comprehensive audit log for all evidence operations.
    
    Forensic Requirements:
    - Immutable logging (no updates/deletes)
    - Timestamps all operations
    - Tracks user/examiner actions
    - Links to evidence for chain of custody
    - Records command execution for reproducibility
    """
    __tablename__ = "audit_logs"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Timestamp (UTC)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True,
                      comment="UTC timestamp of the event")
    
    # User Information
    user = Column(String(256), nullable=False, index=True,
                 comment="User/examiner who performed action")
    ip_address = Column(String(45), nullable=True,
                       comment="IP address of request (IPv4 or IPv6)")
    user_agent = Column(String(512), nullable=True,
                       comment="User agent string from HTTP request")
    
    # Action Information
    action = Column(String(100), nullable=False, index=True,
                   comment="Action performed (upload, verify, scan, recover, etc.)")
    action_category = Column(String(50), nullable=False, index=True,
                            comment="Category: evidence_management, analysis, recovery, export")
    endpoint = Column(String(256), nullable=True,
                     comment="API endpoint called")
    http_method = Column(String(10), nullable=True,
                        comment="HTTP method (GET, POST, etc.)")
    
    # Evidence Reference
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="SET NULL"),
                        nullable=True, index=True,
                        comment="Reference to evidence (null for non-evidence actions)")
    
    # Action Details
    details = Column(Text, nullable=True,
                    comment="JSON or text details about the action")
    parameters = Column(Text, nullable=True,
                       comment="Parameters passed to the action")
    
    # Command Execution (for reproducibility)
    command_executed = Column(Text, nullable=True,
                             comment="Exact command executed (fls, icat, scalpel, etc.)")
    command_output = Column(Text, nullable=True,
                           comment="Command output/results")
    
    # Result Information
    status = Column(String(50), nullable=False, index=True,
                   comment="Status: success, failure, error, in_progress")
    error_message = Column(Text, nullable=True,
                          comment="Error message if action failed")
    
    # Performance Metrics
    duration_ms = Column(Integer, nullable=True,
                        comment="Duration of operation in milliseconds")
    
    # File/Data Changes
    files_affected = Column(Integer, nullable=True,
                           comment="Number of files affected by action")
    bytes_processed = Column(Integer, nullable=True,
                            comment="Bytes processed during operation")
    
    # Forensic Flags
    chain_of_custody = Column(String(50), default="maintained",
                             comment="maintained, broken, unknown")
    requires_review = Column(Integer, default=0,
                            comment="1 if action requires supervisor review")
    
    # Relationships
    evidence = relationship("Evidence", back_populates="audit_logs")
    
    # Composite indexes for common queries
    __table_args__ = (
        Index('idx_audit_timestamp_action', 'timestamp', 'action'),
        Index('idx_audit_evidence_timestamp', 'evidence_id', 'timestamp'),
        Index('idx_audit_user_timestamp', 'user', 'timestamp'),
    )
    
    def __repr__(self):
        return (f"<AuditLog(id={self.id}, timestamp={self.timestamp}, "
                f"user={self.user}, action={self.action})>")
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user': self.user,
            'ip_address': self.ip_address,
            'action': self.action,
            'action_category': self.action_category,
            'endpoint': self.endpoint,
            'http_method': self.http_method,
            'evidence_id': self.evidence_id,
            'details': self.details,
            'parameters': self.parameters,
            'command_executed': self.command_executed,
            'status': self.status,
            'error_message': self.error_message,
            'duration_ms': self.duration_ms,
            'files_affected': self.files_affected,
            'bytes_processed': self.bytes_processed,
            'chain_of_custody': self.chain_of_custody
        }


# Helper function to create audit log entries
def log_action(db, user: str, action: str, evidence_id: int = None, 
               details: str = None, status: str = "success", 
               ip_address: str = None, command: str = None,
               files_affected: int = None, bytes_processed: int = None):
    """
    Convenience function to create audit log entries.
    
    Args:
        db: Database session
        user: Username/examiner name
        action: Action being performed
        evidence_id: Evidence ID if applicable
        details: Additional details about the action
        status: success, failure, error
        ip_address: User's IP address
        command: Command executed (for reproducibility)
        files_affected: Number of files affected
        bytes_processed: Total bytes processed
    
    Returns:
        AuditLog instance
    """
    # Determine action category
    category_map = {
        'upload': 'evidence_management',
        'verify': 'evidence_management',
        'mount': 'evidence_management',
        'unmount': 'evidence_management',
        'scan_partitions': 'analysis',
        'scan_deleted': 'analysis',
        'recover_file': 'recovery',
        'carve_files': 'recovery',
        'download': 'export',
        'generate_report': 'export',
    }
    
    category = category_map.get(action, 'other')
    
    log_entry = AuditLog(
        user=user,
        ip_address=ip_address,
        action=action,
        action_category=category,
        evidence_id=evidence_id,
        details=details,
        command_executed=command,
        status=status,
        files_affected=files_affected,
        bytes_processed=bytes_processed
    )
    
    db.add(log_entry)
    db.commit()
    
    return log_entry
