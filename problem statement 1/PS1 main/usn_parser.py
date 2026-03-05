#!/usr/bin/env python3
"""
USN Journal Parser
Analyzes USN Journal entries to detect actual file creation times
"""

import os
import struct
import datetime
import ctypes
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

# Windows API constants
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
FILE_DEVICE_DISK = 0x00000003
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
USN_DELETE_REASON_FLAGS = 0x00001000

# Define DWORDLONG if not available
if not hasattr(wintypes, 'DWORDLONG'):
    wintypes.DWORDLONG = ctypes.c_uint64

class USN_RECORD_V2(ctypes.Structure):
    """USN_RECORD structure for version 2"""
    _fields_ = [
        ("RecordLength", wintypes.DWORD),
        ("MajorVersion", wintypes.WORD),
        ("MinorVersion", wintypes.WORD),
        ("FileReferenceNumber", wintypes.DWORDLONG),
        ("ParentFileReferenceNumber", wintypes.DWORDLONG),
        ("Usn", wintypes.DWORDLONG),
        ("TimeStamp", wintypes.LARGE_INTEGER),
        ("Reason", wintypes.DWORD),
        ("SourceInfo", wintypes.WORD),
        ("SecurityId", wintypes.WORD),
        ("FileAttributes", wintypes.DWORD),
        ("FileNameLength", wintypes.WORD),
        ("FileNameOffset", wintypes.WORD),
        ("FileName", wintypes.WCHAR * 1)  # Variable length
    ]

class USNJournalParser:
    """Parser for NTFS USN Journal"""
    
    def __init__(self, volume_path: str):
        """
        Initialize USN Journal parser
        
        Args:
            volume_path: Volume path (e.g., "C:")
        """
        self.volume_path = volume_path.rstrip('\\')
        self.volume_handle = None
        
    def open_volume(self) -> bool:
        """Open volume handle for USN journal access"""
        try:
            # Create file handle to volume
            volume_path = f"\\\\.\\{self.volume_path}"
            self.volume_handle = ctypes.windll.kernel32.CreateFileW(
                volume_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            if self.volume_handle == -1 or self.volume_handle is None:
                print(f"Failed to open volume {self.volume_path}")
                return False
                
            return True
            
        except Exception as e:
            print(f"Error opening volume: {e}")
            return False
            
    def close_volume(self):
        """Close volume handle"""
        if self.volume_handle:
            ctypes.windll.kernel32.CloseHandle(self.volume_handle)
            self.volume_handle = None
            
    def get_usn_journal_info(self) -> Optional[Dict]:
        """Get USN Journal information"""
        try:
            # Define FSCTL_QUERY_USN_JOURNAL control code
            FSCTL_QUERY_USN_JOURNAL = 0x000900f4
            
            # Input buffer (empty for query)
            input_size = 0
            
            # Output buffer for USN_JOURNAL_DATA
            class USN_JOURNAL_DATA(ctypes.Structure):
                _fields_ = [
                    ("UsnJournalID", wintypes.DWORDLONG),
                    ("FirstUsn", wintypes.DWORDLONG),
                    ("NextUsn", wintypes.DWORDLONG),
                    ("LowestValidUsn", wintypes.DWORDLONG),
                    ("MaxUsn", wintypes.DWORDLONG),
                    ("MaximumSize", wintypes.DWORDLONG),
                    ("AllocationDelta", wintypes.DWORDLONG)
                ]
            
            output_size = ctypes.sizeof(USN_JOURNAL_DATA)
            output_buffer = ctypes.create_string_buffer(output_size)
            bytes_returned = wintypes.DWORD()
            
            # Send control code
            result = ctypes.windll.kernel32.DeviceIoControl(
                self.volume_handle,
                FSCTL_QUERY_USN_JOURNAL,
                None,
                input_size,
                output_buffer,
                output_size,
                ctypes.byref(bytes_returned),
                None
            )
            
            if not result:
                print("Failed to query USN journal")
                return None
                
            # Parse output
            journal_data = USN_JOURNAL_DATA.from_buffer(output_buffer)
            
            return {
                'journal_id': journal_data.UsnJournalID,
                'first_usn': journal_data.FirstUsn,
                'next_usn': journal_data.NextUsn,
                'lowest_valid_usn': journal_data.LowestValidUsn,
                'max_usn': journal_data.MaxUsn,
                'maximum_size': journal_data.MaximumSize,
                'allocation_delta': journal_data.AllocationDelta
            }
            
        except Exception as e:
            print(f"Error getting USN journal info: {e}")
            return None
            
    def read_usn_journal(self, start_usn: int = 0, max_bytes: int = 65536) -> List[Dict]:
        """
        Read USN Journal entries
        
        Args:
            start_usn: Starting USN to read from
            max_bytes: Maximum bytes to read
            
        Returns:
            List of USN entries
        """
        try:
            # Define FSCTL_READ_USN_JOURNAL control code
            FSCTL_READ_USN_JOURNAL = 0x000900f3
            
            # Input buffer for READ_USN_JOURNAL_DATA
            class READ_USN_JOURNAL_DATA(ctypes.Structure):
                _fields_ = [
                    ("StartUsn", wintypes.DWORDLONG),
                    ("ReasonMask", wintypes.DWORD),
                    ("ReturnOnlyOnClose", wintypes.BOOL),
                    ("Timeout", wintypes.DWORD),
                    ("BytesToWaitFor", wintypes.DWORD),
                    ("UsnJournalID", wintypes.DWORDLONG)
                ]
            
            # We want all reasons
            REASON_MASK = 0xFFFFFFFF
            
            input_data = READ_USN_JOURNAL_DATA()
            input_data.StartUsn = start_usn
            input_data.ReasonMask = REASON_MASK
            input_data.ReturnOnlyOnClose = False
            input_data.Timeout = 0
            input_data.BytesToWaitFor = 0
            
            # Get journal ID first
            journal_info = self.get_usn_journal_info()
            if not journal_info:
                return []
                
            input_data.UsnJournalID = journal_info['journal_id']
            
            # Output buffer
            output_size = max_bytes
            output_buffer = ctypes.create_string_buffer(output_size)
            bytes_returned = wintypes.DWORD()
            
            # Send control code
            result = ctypes.windll.kernel32.DeviceIoControl(
                self.volume_handle,
                FSCTL_READ_USN_JOURNAL,
                ctypes.byref(input_data),
                ctypes.sizeof(input_data),
                output_buffer,
                output_size,
                ctypes.byref(bytes_returned),
                None
            )
            
            if not result:
                print("Failed to read USN journal")
                return []
                
            # Parse USN records
            entries = []
            offset = 8  # Skip NextUsn (8 bytes)
            
            while offset < bytes_returned.value:
                if offset + ctypes.sizeof(USN_RECORD_V2) > bytes_returned.value:
                    break
                    
                # Read record header
                record_buffer = output_buffer[offset:]
                record = USN_RECORD_V2.from_buffer(record_buffer)
                
                if record.RecordLength == 0:
                    break
                    
                # Extract filename
                filename_offset = offset + record.FileNameOffset
                filename_bytes = output_buffer[filename_offset:filename_offset + record.FileNameLength * 2]
                filename = filename_bytes.decode('utf-16le').rstrip('\x00')
                
                # Convert timestamp
                timestamp = self._filetime_to_datetime(record.TimeStamp)
                
                # Parse reason flags
                reasons = self._parse_reason_flags(record.Reason)
                
                entry = {
                    'file_reference': record.FileReferenceNumber,
                    'parent_reference': record.ParentFileReferenceNumber,
                    'usn': record.Usn,
                    'timestamp': timestamp.isoformat() if timestamp else None,
                    'reason': record.Reason,
                    'reasons': reasons,
                    'source_info': record.SourceInfo,
                    'security_id': record.SecurityId,
                    'file_attributes': record.FileAttributes,
                    'filename': filename
                }
                
                entries.append(entry)
                
                # Move to next record
                offset += record.RecordLength
                
            return entries
            
        except Exception as e:
            print(f"Error reading USN journal: {e}")
            return []
            
    def _parse_reason_flags(self, reason: int) -> List[str]:
        """Parse USN reason flags into human-readable names"""
        reasons = []
        
        # Reason flags mapping
        reason_map = {
            0x00000001: "DATA_OVERWRITE",
            0x00000002: "DATA_EXTEND",
            0x00000004: "DATA_TRUNCATION",
            0x00000008: "DATA_WRITE",
            0x00000010: "FILE_CREATE",
            0x00000020: "FILE_DELETE",
            0x00000040: "EA_CHANGE",
            0x00000080: "SECURITY_CHANGE",
            0x00000100: "RENAME_OLD_NAME",
            0x00000200: "RENAME_NEW_NAME",
            0x00000400: "INDEXABLE_CHANGE",
            0x00000800: "BASIC_INFO_CHANGE",
            0x00001000: "HARD_LINK_CHANGE",
            0x00002000: "COMPRESSION_CHANGE",
            0x00004000: "ENCRYPTION_CHANGE",
            0x00008000: "OBJECT_ID_CHANGE",
            0x00010000: "REPARSE_POINT_CHANGE",
            0x00020000: "STREAM_CHANGE",
            0x00040000: "CLOSE"
        }
        
        for flag, name in reason_map.items():
            if reason & flag:
                reasons.append(name)
                
        return reasons
        
    def _filetime_to_datetime(self, filetime: int) -> Optional[datetime.datetime]:
        """Convert FILETIME to datetime"""
        try:
            if filetime == 0:
                return None
                
            # FILETIME is 100-nanosecond intervals since Jan 1, 1601
            epoch_start = datetime.datetime(1601, 1, 1)
            microseconds = filetime / 10
            return epoch_start + datetime.timedelta(microseconds=microseconds)
            
        except Exception:
            return None
            
    def find_file_creation_events(self, filename: str, max_hours: int = 24) -> List[Dict]:
        """
        Find file creation events for a specific filename
        
        Args:
            filename: Filename to search for
            max_hours: Maximum hours to search back
            
        Returns:
            List of creation events
        """
        try:
            if not self.open_volume():
                return []
                
            # Read USN journal
            entries = self.read_usn_journal()
            
            # Filter for file creation events
            creation_events = []
            current_time = datetime.datetime.now()
            
            for entry in entries:
                # Check if this is a file creation event
                if "FILE_CREATE" in entry['reasons']:
                    # Check filename match (case-insensitive)
                    if entry['filename'].lower() == filename.lower():
                        # Check time window
                        if entry['timestamp']:
                            entry_time = datetime.datetime.fromisoformat(entry['timestamp'])
                            time_diff = (current_time - entry_time).total_seconds() / 3600
                            
                            if time_diff <= max_hours:
                                creation_events.append(entry)
                                
            self.close_volume()
            return creation_events
            
        except Exception as e:
            print(f"Error finding file creation events: {e}")
            return []
            
    def get_recent_file_activity(self, hours: int = 24) -> List[Dict]:
        """
        Get all file activity within specified time window
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of recent file activities
        """
        try:
            if not self.open_volume():
                return []
                
            entries = self.read_usn_journal()
            
            # Filter by time
            current_time = datetime.datetime.now()
            recent_activities = []
            
            for entry in entries:
                if entry['timestamp']:
                    entry_time = datetime.datetime.fromisoformat(entry['timestamp'])
                    time_diff = (current_time - entry_time).total_seconds() / 3600
                    
                    if time_diff <= hours:
                        recent_activities.append(entry)
                        
            self.close_volume()
            return recent_activities
            
        except Exception as e:
            print(f"Error getting recent file activity: {e}")
            return []
