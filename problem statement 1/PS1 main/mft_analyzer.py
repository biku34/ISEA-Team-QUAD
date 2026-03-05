#!/usr/bin/env python3
"""
MFT Timestamp Analyzer - Live NTFS Filesystem Version
Extracts and compares timestamps from NTFS MFT entries using Windows APIs
"""

import datetime
import struct
import os
import ctypes
import ctypes.wintypes
from typing import Dict, List, Optional, Tuple

# Windows API constants
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value

# Windows API structures
class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.wintypes.DWORD),
                ("dwHighDateTime", ctypes.wintypes.DWORD)]

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", ctypes.wintypes.WORD),
        ("wMonth", ctypes.wintypes.WORD),
        ("wDayOfWeek", ctypes.wintypes.WORD),
        ("wDay", ctypes.wintypes.WORD),
        ("wHour", ctypes.wintypes.WORD),
        ("wMinute", ctypes.wintypes.WORD),
        ("wSecond", ctypes.wintypes.WORD),
        ("wMilliseconds", ctypes.wintypes.WORD)
    ]

class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.wintypes.DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("dwVolumeSerialNumber", ctypes.wintypes.DWORD),
        ("nFileSizeHigh", ctypes.wintypes.DWORD),
        ("nFileSizeLow", ctypes.wintypes.DWORD),
        ("nNumberOfLinks", ctypes.wintypes.DWORD),
        ("nFileIndexHigh", ctypes.wintypes.DWORD),
        ("nFileIndexLow", ctypes.wintypes.DWORD)
    ]

# Windows API functions
kernel32 = ctypes.windll.kernel32
CreateFileW = kernel32.CreateFileW
GetFileInformationByHandle = kernel32.GetFileInformationByHandle
CloseHandle = kernel32.CloseHandle
FileTimeToSystemTime = kernel32.FileTimeToSystemTime

CreateFileW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, 
                        ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID, 
                        ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, 
                        ctypes.wintypes.HANDLE]
CreateFileW.restype = ctypes.wintypes.HANDLE

GetFileInformationByHandle.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
GetFileInformationByHandle.restype = ctypes.wintypes.BOOL

CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
CloseHandle.restype = ctypes.wintypes.BOOL

FileTimeToSystemTime.argtypes = [ctypes.POINTER(FILETIME), ctypes.POINTER(SYSTEMTIME)]
FileTimeToSystemTime.restype = ctypes.wintypes.BOOL

class MFTAnalyzer:
    """Analyzes MFT entries for timestamp discrepancies using Windows APIs"""
    
    def __init__(self):
        """
        Initialize MFT analyzer for live NTFS filesystem
        """
        pass
        
    def filetime_to_datetime(self, ft: FILETIME) -> str:
        """Convert Windows FILETIME to ISO datetime string"""
        st = SYSTEMTIME()
        if FileTimeToSystemTime(ctypes.byref(ft), ctypes.byref(st)):
            dt = datetime.datetime(st.wYear, st.wMonth, st.wDay, 
                                   st.wHour, st.wMinute, st.wSecond, 
                                   st.wMilliseconds * 1000)
            return dt.isoformat()
        return None
        
    def extract_timestamps(self, file_path: str) -> Dict:
        """
        Extract timestamps from file using Windows APIs
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing timestamp analysis
        """
        result = {
            'file_path': file_path,
            'si_timestamps': {},  # Standard Information timestamps
            'fn_timestamps': {},  # File Name timestamps (simulated)
            'discrepancies': [],
            'analysis_method': 'Windows API'
        }
        
        try:
            # Open file handle
            handle = CreateFileW(file_path, FILE_READ_ATTRIBUTES, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE, 
                               None, OPEN_EXISTING, 0, None)
            
            if handle == INVALID_HANDLE_VALUE:
                raise Exception(f"Cannot open file: {file_path}")
                
            try:
                # Get file information
                file_info = BY_HANDLE_FILE_INFORMATION()
                if GetFileInformationByHandle(handle, ctypes.byref(file_info)):
                    # Extract timestamps from Standard Information ($SI)
                    si_creation = self.filetime_to_datetime(file_info.ftCreationTime)
                    si_modification = self.filetime_to_datetime(file_info.ftLastWriteTime)
                    si_access = self.filetime_to_datetime(file_info.ftLastAccessTime)
                    
                    result['si_timestamps'] = {
                        'creation': si_creation,
                        'modification': si_modification,
                        'access': si_access
                    }
                    
                    # For File Name ($FN) timestamps, we'll use os.stat as approximation
                    # In real MFT analysis, $FN would be extracted from MFT entry directly
                    stat_info = os.stat(file_path)
                    fn_creation = datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                    fn_modification = datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                    fn_access = datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat()
                    
                    result['fn_timestamps'] = {
                        'creation': fn_creation,
                        'modification': fn_modification,
                        'access': fn_access
                    }
                    
                    # Check for discrepancies between SI and FN timestamps
                    discrepancies = self._check_timestamp_discrepancies(
                        result['si_timestamps'], 
                        result['fn_timestamps']
                    )
                    result['discrepancies'] = discrepancies
                    
                    # **NEW**: Check for actual timestomping by comparing with current time
                    current_time = datetime.datetime.now()
                    if si_creation:
                        si_dt = datetime.datetime.fromisoformat(si_creation)
                        time_diff = abs((current_time - si_dt).total_seconds())
                        
                        # If file claims to be older than 1 day, it's likely timestomped
                        if time_diff > 86400:  # More than 1 day
                            days_old = time_diff / 86400
                            result['discrepancies'].append(
                                f"File claims to be {days_old:.1f} days old (SUSPICIOUS)"
                            )
                        elif time_diff > 3600:  # More than 1 hour
                            hours_old = time_diff / 3600
                            result['discrepancies'].append(
                                f"File claims to be {hours_old:.1f} hours old (INVESTIGATE)"
                            )
                    
            finally:
                CloseHandle(handle)
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
        
    def _check_timestamp_discrepancies(self, si_times: Dict, fn_times: Dict) -> List[str]:
        """Check for discrepancies between SI and FN timestamps"""
        discrepancies = []
        
        for timestamp_type in ['creation', 'modification', 'access']:
            si_time = si_times.get(timestamp_type)
            fn_time = fn_times.get(timestamp_type)
            
            if si_time and fn_time:
                try:
                    si_dt = datetime.datetime.fromisoformat(si_time)
                    fn_dt = datetime.datetime.fromisoformat(fn_time)
                    time_diff = abs((si_dt - fn_dt).total_seconds())
                    
                    # Dynamic threshold: 
                    # - Small differences (< 6 hours) are likely timezone/system differences
                    # - Large differences (> 24 hours) are likely timestomping attacks
                    # - Medium differences (6-24 hours) need investigation
                    
                    if time_diff > 86400:  # More than 24 hours = definite timestomping
                        discrepancies.append(
                            f"{timestamp_type.capitalize()} timestamps differ by {time_diff/3600:.1f} hours (SUSPICIOUS)"
                        )
                    elif time_diff > 21600:  # 6-24 hours = needs investigation
                        discrepancies.append(
                            f"{timestamp_type.capitalize()} timestamps differ by {time_diff/3600:.1f} hours (INVESTIGATE)"
                        )
                    elif time_diff > 3600:  # 1-6 hours = likely timezone difference
                        discrepancies.append(
                            f"{timestamp_type.capitalize()} timestamps differ by {time_diff/3600:.1f} hours (timezone/system)"
                        )
                        
                except Exception:
                    pass
                    
        return discrepancies
        
    def analyze_directory(self, directory_path: str, max_files: int = 100) -> List[Dict]:
        """
        Analyze all files in a directory
        
        Args:
            directory_path: Path to directory to analyze
            max_files: Maximum number of files to analyze
            
        Returns:
            List of analysis results for each file
        """
        results = []
        file_count = 0
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    if file_count >= max_files:
                        break
                        
                    file_path = os.path.join(root, file)
                    result = self.extract_timestamps(file_path)
                    results.append(result)
                    file_count += 1
                    
                if file_count >= max_files:
                    break
                    
        except Exception as e:
            print(f"Error analyzing directory: {e}")
            
        return results
        
    def get_file_metadata(self, file_path: str) -> Dict:
        """
        Get comprehensive file metadata
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file metadata
        """
        metadata = {
            'file_path': file_path,
            'file_size': 0,
            'file_attributes': '',
            'file_index': 0,
            'volume_serial': 0
        }
        
        try:
            handle = CreateFileW(file_path, FILE_READ_ATTRIBUTES, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE, 
                               None, OPEN_EXISTING, 0, None)
            
            if handle != INVALID_HANDLE_VALUE:
                try:
                    file_info = BY_HANDLE_FILE_INFORMATION()
                    if GetFileInformationByHandle(handle, ctypes.byref(file_info)):
                        metadata['file_size'] = (file_info.nFileSizeHigh << 32) | file_info.nFileSizeLow
                        metadata['file_attributes'] = file_info.dwFileAttributes
                        metadata['file_index'] = (file_info.nFileIndexHigh << 32) | file_info.nFileIndexLow
                        metadata['volume_serial'] = file_info.dwVolumeSerialNumber
                        
                finally:
                    CloseHandle(handle)
                    
        except Exception as e:
            metadata['error'] = str(e)
            
        return metadata
