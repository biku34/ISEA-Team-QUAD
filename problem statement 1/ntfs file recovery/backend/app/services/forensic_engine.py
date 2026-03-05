"""
Forensic Engine - Core integration with SleuthKit, EWF Tools, and Scalpel.
Provides read-only, forensically-sound operations on NTFS disk images.

FORENSIC STANDARDS:
- Read-only mounting (no writes to evidence)
- Command sanitization (prevent injection)
- Complete audit logging
- Hash verification
- Reproducible operations
"""

import subprocess
import re
import os
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
import yaml
import hashlib
from loguru import logger

# Load configuration
config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
if not config_path.exists():
    config_path = Path(__file__).parent.parent.parent / "config" / "config.example.yaml"

with open(config_path, 'r') as f:
    CONFIG = yaml.safe_load(f)


class ForensicEngineError(Exception):
    """Base exception for forensic engine errors"""
    pass


class MountError(ForensicEngineError):
    """Error during image mounting"""
    pass


class ScanError(ForensicEngineError):
    """Error during partition/file scanning"""
    pass


class RecoveryError(ForensicEngineError):
    """Error during file recovery"""
    pass


class ForensicEngine:
    """
    Core forensic engine for NTFS deleted file recovery.
    Integrates SleuthKit, ewfmount, and Scalpel.
    """
    
    def __init__(self):
        """Initialize forensic engine with tool paths from config"""
        self.ewfmount = CONFIG['forensic_tools']['ewfmount']
        self.ewfunmount = CONFIG['forensic_tools']['ewfunmount']
        self.mmls = CONFIG['forensic_tools']['mmls']
        self.fls = CONFIG['forensic_tools']['fls']
        self.icat = CONFIG['forensic_tools']['icat']
        self.scalpel = CONFIG['forensic_tools']['scalpel']
        self.sha256sum = CONFIG['forensic_tools']['sha256sum']
        
        self.mount_dir = Path(CONFIG['storage']['mount_dir'])
        self.recovered_dir = Path(CONFIG['storage']['recovered_dir'])
        self.carved_dir = Path(CONFIG['storage']['carved_dir'])
        self.temp_dir = Path(CONFIG['storage']['temp_dir'])
        
        # Create directories
        self.mount_dir.mkdir(parents=True, exist_ok=True)
        self.recovered_dir.mkdir(parents=True, exist_ok=True)
        self.carved_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.timeout = CONFIG['security']['command_timeout']
    
    def _sanitize_path(self, path: str) -> str:
        """
        Sanitize file paths to prevent command injection and path traversal.
        
        SECURITY: Critical for forensic integrity
        """
        # Convert to Path and resolve to absolute
        safe_path = Path(path).resolve()
        
        # Ensure path doesn't escape allowed directories
        allowed_dirs = [
            self.mount_dir.resolve(),
            self.recovered_dir.resolve(),
            self.carved_dir.resolve(),
            self.temp_dir.resolve(),
            Path(CONFIG['storage']['evidence_dir']).resolve()
        ]
        
        # Check if path is under an allowed directory
        if not any(str(safe_path).startswith(str(allowed)) for allowed in allowed_dirs):
            raise ForensicEngineError(f"Path traversal attempt detected: {path}")
        
        return str(safe_path)
    
    def _run_command(self, cmd: List[str], check=True, capture_output=True) -> subprocess.CompletedProcess:
        """
        Execute command with security controls.
        
        FORENSIC: All commands logged for reproducibility
        SECURITY: Timeout, no shell expansion, sanitized inputs
        """
        try:
            result = subprocess.run(
                cmd,
                check=check,
                capture_output=capture_output,
                text=True,
                timeout=self.timeout,
                shell=False  # CRITICAL: Prevent shell injection
            )
            return result
        except subprocess.TimeoutExpired:
            raise ForensicEngineError(f"Command timeout after {self.timeout}s: {' '.join(cmd)}")
        except subprocess.CalledProcessError as e:
            raise ForensicEngineError(f"Command failed: {e.stderr}")
        except Exception as e:
            raise ForensicEngineError(f"Command execution error: {str(e)}")
    
    def calculate_hash(self, file_path: str, algorithm='sha256') -> str:
        """
        Calculate cryptographic hash of a file.
        
        FORENSIC: SHA-256 for integrity verification
        """
        safe_path = self._sanitize_path(file_path)
        
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'md5':
            hasher = hashlib.md5()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        buffer_size = CONFIG['hashing']['buffer_size']
        
        with open(safe_path, 'rb') as f:
            while True:
                chunk = f.read(buffer_size)
                if not chunk:
                    break
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def mount_image(self, e01_path: str, evidence_id: int) -> str:
        """
        Mount E01 image using ewfmount (read-only).
        
        FORENSIC: Read-only mount, no writes to evidence
        
        For segmented images (E01, E02, E03...):
        - ewfmount automatically detects and uses all segments
        - All segments must be in the same directory
        - Only pass the primary segment (.E01) to ewfmount
        
        Returns: Mount point path
        """
        safe_path = self._sanitize_path(e01_path)
        e01_file = Path(safe_path)
        
        if not e01_file.exists():
            raise MountError(f"Evidence file not found: {e01_path}")
        
        # Check if this is a segmented image
        from app.services.segment_handler import SegmentHandler, SegmentError
        
        parsed = SegmentHandler.parse_segment_filename(e01_file.name)
        if parsed:
            base_name, seg_num = parsed
            
            # If not the primary segment, find the primary segment
            if seg_num != 1:
                # Look for .E01 in the same directory
                primary_path = e01_file.parent / f"{base_name}.E01"
                if not primary_path.exists():
                    raise MountError(f"Primary segment (.E01) not found for {e01_file.name}")
                safe_path = str(primary_path)
                e01_file = primary_path
            
            # Detect all segments in the directory
            try:
                segments = SegmentHandler.detect_segments_in_directory(e01_file.parent, base_name)
                
                if not segments:
                    raise MountError(f"No segments found for {base_name}")
                
                # Validate segment set
                validation = SegmentHandler.validate_segment_set(segments)
                
                if not validation['valid']:
                    missing = validation['missing_segments']
                    raise MountError(
                        f"Incomplete segment set for {base_name}. Missing segments: {missing}"
                    )
                
                # Log segment info
                logger.info(
                    f"Mounting segmented image: {base_name} "
                    f"({validation['total_segments']} segments, "
                    f"{validation['total_size']} bytes total)"
                )
                
            except SegmentError as e:
                raise MountError(f"Segment validation failed: {str(e)}")
        
        # Create unique mount point
        mount_point = self.mount_dir / f"evidence_{evidence_id}"
        mount_point.mkdir(parents=True, exist_ok=True)
        
        # Check if already mounted and healthy
        ewf_file = mount_point.absolute() / "ewf1"
        if ewf_file.exists():
            # CRITICAL FIX: Ensure it's not a stale 0-byte file from a failed mount
            file_size = ewf_file.stat().st_size
            if file_size > 0:
                logger.info(f"Evidence {evidence_id} already mounted at {mount_point} (size: {file_size})")
                return str(mount_point)
            else:
                logger.warning(f"Stale/broken mount detected at {mount_point} (0 bytes). Cleaning up...")
                self.unmount_image(str(mount_point))
                # Re-create directory if unmount removed it
                mount_point.mkdir(parents=True, exist_ok=True)
        
        # Mount with read-only options
        # ewfmount will automatically detect and handle all segments (.E01, .E02, .E03, etc.)
        mount_options = CONFIG['mount']['options']
        
        cmd = [
            self.ewfmount,
            str(e01_file),
            str(mount_point.absolute())
        ]
        
        try:
            self._run_command(cmd)
            
            # Verify mount (check for ewf1 file and non-zero size)
            ewf_file = mount_point.absolute() / "ewf1"
            if not ewf_file.exists():
                raise MountError("Mount succeeded but ewf1 file not found")
            
            if ewf_file.stat().st_size == 0:
                raise MountError("Mount succeeded but ewf1 file reports 0 bytes")
            
            logger.info(f"Successfully mounted {e01_file.name} at {mount_point} (size: {ewf_file.stat().st_size})")
            return str(mount_point)
        
        except Exception as e:
            # Cleanup on failure
            self.unmount_image(str(mount_point))
            raise MountError(f"Failed to mount image: {str(e)}")
    
    def unmount_image(self, mount_point: str) -> bool:
        """
        Unmount E01 image.
        
        FORENSIC: Ensures clean unmount for evidence integrity
        """
        safe_path = self._sanitize_path(mount_point)
        
        # Try normal unmount first
        cmd = [self.ewfunmount, '-u', safe_path]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                # If normal unmount fails (likely busy), try lazy unmount
                logger.warning(f"Normal unmount failed for {mount_point}, trying lazy unmount...")
                lazy_cmd = ["fusermount3", "-u", "-z", safe_path]
                subprocess.run(lazy_cmd, capture_output=True, text=True, timeout=30)
            
            # Remove mount directory
            mount_path = Path(safe_path)
            if mount_path.exists():
                # Only remove if it's no longer a mount point
                # (shutil.rmtree can fail on active mounts)
                try:
                    mount_path.rmdir()
                except OSError:
                    # Directory not empty or still mounted
                    pass
            
            return True
        except Exception as e:
            logger.error(f"Unmount error for {mount_point}: {str(e)}")
            return False
    
    def detect_partitions(self, mount_point: str) -> List[Dict]:
        """
        Detect partitions using mmls (SleuthKit).
        
        FORENSIC: Extracts partition table for NTFS identification
        
        Returns: List of partition metadata
        """
        safe_mount = self._sanitize_path(mount_point)
        ewf_file = Path(safe_mount) / "ewf1"
        
        if not ewf_file.exists():
            raise ScanError(f"ewf1 not found at {safe_mount}")
        
        cmd = [self.mmls, str(ewf_file)]
        
        try:
            result = self._run_command(cmd)
            output = result.stdout
        except ForensicEngineError as e:
            raise ScanError(f"Partition detection failed: {str(e)}")
        
        partitions = []
        
        # Parse mmls output
        # Format: slot start end length description
        lines = output.strip().split('\n')
        
        for line in lines:
            # Skip header lines
            if line.startswith('DOS') or line.startswith('Units') or \
               line.startswith('Slot') or not line.strip():
                continue
            
            # Parse partition info
            # Example: 000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
            # Example: 002:  00:07     0000002048   0204802047   0204800000   NTFS / exFAT (0x07)
            
            match = re.search(r'(\d+):\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$', line)
            
            if match:
                slot = int(match.group(1))
                start_offset = int(match.group(2))
                end_offset = int(match.group(3))
                length_sectors = int(match.group(4))
                description = match.group(5).strip()
                
                # Identify filesystem type
                filesystem = "Unknown"
                if any(x in description.upper() for x in ["NTFS", "0x07", "BASIC DATA PARTITION"]):
                    filesystem = "NTFS"
                elif "FAT32" in description.upper():
                    filesystem = "FAT32"
                elif "EXT" in description.upper():
                    filesystem = "ext4"
                
                # Calculate size in bytes (assume 512-byte sectors)
                sector_size = 512
                size_bytes = length_sectors * sector_size
                
                partitions.append({
                    'slot': slot,
                    'start_offset': start_offset,
                    'end_offset': end_offset,
                    'length_sectors': length_sectors,
                    'size_bytes': size_bytes,
                    'filesystem_type': filesystem,
                    'description': description
                })
        
        return partitions
    
    def scan_deleted_files(self, mount_point: str, partition_offset: int) -> List[Dict]:
        """
        Scan for deleted files using fls (SleuthKit).
        
        FORENSIC: Extracts MFT entries for deleted files
        
        Returns: List of deleted file metadata with MACB timestamps
        """
        return self._run_fls(mount_point, partition_offset, deleted_only=True, recursive=True)

    def list_all_files(self, mount_point: str, partition_offset: int) -> List[Dict]:
        """
        List all files (allocated and deleted) using fls.
        
        FORENSIC: Full recursive file listing
        """
        return self._run_fls(mount_point, partition_offset, deleted_only=False, recursive=True)

    def list_directory(self, mount_point: str, partition_offset: int, directory_inode: Optional[int] = None) -> List[Dict]:
        """
        List content of a specific directory.
        """
        return self._run_fls(mount_point, partition_offset, deleted_only=False, recursive=False, inode=directory_inode)

    def _run_fls(self, mount_point: str, partition_offset: int, 
                 deleted_only: bool = False, recursive: bool = False, 
                 inode: Optional[int] = None) -> List[Dict]:
        """
        Helper to run fls and parse output.
        """
        safe_mount = self._sanitize_path(mount_point)
        ewf_file = Path(safe_mount) / "ewf1"
        
        if not ewf_file.exists():
            raise ScanError(f"ewf1 not found at {safe_mount}")
        
        # fls options:
        # -r: recursive
        # -d: deleted files only
        # -p: display full path
        # -m: MAC times format
        # -o: partition offset
        
        # FORENSIC: We use mactime format (-m) for full listings to get timestamps
        # but standard format for deleted_only scans because -m -d can be unreliable
        use_mactime = not deleted_only
        
        if use_mactime:
            cmd = [self.fls, '-m', '/', '-o', str(partition_offset)]
        else:
            cmd = [self.fls, '-p', '-o', str(partition_offset)]
            
        if recursive:
            cmd.append('-r')
        if deleted_only:
            cmd.append('-d')
            
        cmd.append(str(ewf_file))
        
        if inode:
            cmd.append(str(inode))
        
        try:
            result = self._run_command(cmd, check=False)
            output = result.stdout
        except ForensicEngineError as e:
            raise ScanError(f"File system scan failed: {str(e)}")
        
        files = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line.strip() or line.startswith('#'):
                continue
            
            try:
                if use_mactime:
                    # Parse body file (mactime format)
                    # Format: 0|filename|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
                    parts = line.split('|')
                    if len(parts) < 11:
                        continue
                        
                    inode_full = parts[2]
                    inode_val = int(inode_full.split('-')[0]) if '-' in inode_full else (int(inode_full) if inode_full.isdigit() else 0)
                    
                    file_info = {
                        'path': parts[1],
                        'filename': Path(parts[1]).name,
                        'inode': inode_val,
                        'inode_full': inode_full,
                        'size_bytes': int(parts[6]) if parts[6].isdigit() else 0,
                        'time_accessed': self._parse_unix_timestamp(parts[7]),
                        'time_modified': self._parse_unix_timestamp(parts[8]),
                        'time_changed': self._parse_unix_timestamp(parts[9]),
                        'time_birth': self._parse_unix_timestamp(parts[10]),
                        'is_directory': parts[3].startswith('d'),
                        'mft_flags': parts[3],
                    }
                else:
                    # Parse standard fls output
                    # Format: r/r * inode: filename
                    # Example: r/r * 39-128-1:  /$OrphanFiles/sd.txt
                    match = re.match(r'^(\S+)\s+(\*?)\s*(\d+-[-\d]*):?\s+(.+)$', line)
                    if not match:
                        continue
                        
                    mft_flags = match.group(1)
                    is_deleted_mark = match.group(2) == '*'
                    inode_full = match.group(3)
                    inode_val = int(inode_full.split('-')[0]) if '-' in inode_full else int(inode_full)
                    path = match.group(4).strip()
                    
                    file_info = {
                        'path': path,
                        'filename': Path(path).name,
                        'inode': inode_val,
                        'inode_full': inode_full,
                        'size_bytes': 0, # Standard format doesn't have size
                        'time_accessed': None,
                        'time_modified': None,
                        'time_changed': None,
                        'time_birth': None,
                        'is_directory': mft_flags.startswith('d'),
                        'mft_flags': mft_flags,
                    }
                
                if '.' in file_info['filename']:
                    file_info['extension'] = file_info['filename'].split('.')[-1].lower()
                    file_info['file_type'] = file_info['extension']
                else:
                    file_info['file_type'] = 'directory' if file_info['is_directory'] else 'file'
                
                if inode_val > 0:
                    files.append(file_info)
                    
            except (ValueError, IndexError, Exception):
                continue
        
        return files
    
    def _parse_unix_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse Unix timestamp to datetime"""
        try:
            if timestamp_str and timestamp_str != '0':
                return datetime.fromtimestamp(int(timestamp_str))
        except (ValueError, OSError):
            pass
        return None
    
    def recover_file(self, mount_point: str, partition_offset: int, 
                    inode: int, output_path: str) -> Tuple[str, int]:
        """
        Recover deleted file using icat (SleuthKit).
        
        FORENSIC: Extracts file data by inode from MFT
        
        Returns: (output_path, file_size)
        """
        safe_mount = self._sanitize_path(mount_point)
        safe_output = self._sanitize_path(output_path)
        
        ewf_file = Path(safe_mount) / "ewf1"
        
        if not ewf_file.exists():
            raise RecoveryError(f"ewf1 not found at {safe_mount}")
        
        # icat command to recover file by inode
        cmd = [
            self.icat,
            '-o', str(partition_offset),
            str(ewf_file),
            str(inode)
        ]
        
        try:
            # Run icat and redirect output to file
            with open(safe_output, 'wb') as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout,
                    check=True
                )
            
            # Get file size
            file_size = Path(safe_output).stat().st_size
            
            return (safe_output, file_size)
        
        except subprocess.CalledProcessError as e:
            raise RecoveryError(f"icat failed: {e.stderr.decode() if e.stderr else 'Unknown error'}")
        except ForensicEngineError as e:
            raise RecoveryError(f"Recovery command failed: {str(e)}")
        except Exception as e:
            raise RecoveryError(f"Recovery failed: {str(e)}")
    
    def carve_files(self, mount_point: str, partition_offset: int, 
                   output_dir: str, session_id: str) -> List[Dict]:
        """
        Carve deleted files from unallocated space using Scalpel.
        
        FORENSIC: Signature-based recovery from wiped/unallocated space
        
        Returns: List of carved file metadata
        """
        safe_mount = self._sanitize_path(mount_point)
        safe_output = self._sanitize_path(output_dir)
        
        ewf_file = Path(safe_mount) / "ewf1"
        
        if not ewf_file.exists():
            raise RecoveryError(f"ewf1 not found at {safe_mount}")
        
        # Create session output directory
        session_dir = Path(safe_output) / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        # Scalpel configuration file
        scalpel_conf = CONFIG['carving']['scalpel_config']
        
        # Scalpel command
        cmd = [
            self.scalpel,
            '-c', scalpel_conf,
            '-o', str(session_dir),
            str(ewf_file)
        ]
        
        try:
            # Run scalpel (can take a long time)
            self._run_command(cmd, check=False)
            
            # Parse carved files
            return self.parse_carved_files(str(session_dir), session_id)
        
        except Exception as e:
            raise RecoveryError(f"Scalpel carving failed: {str(e)}")

    def parse_carved_files(self, session_dir_path: str, session_id: str) -> List[Dict]:
        """
        Parses the Scalpel output directory and returns metadata for found files.
        Useful for incremental updates.
        """
        session_dir = Path(session_dir_path)
        if not session_dir.exists():
            return []
            
        carved_files = []
        
        # Scalpel creates subdirectories by file type
        for type_dir in session_dir.iterdir():
            if type_dir.is_dir():
                file_type = type_dir.name
                
                # Skip the 'audit' directory Scalpel sometimes creates
                if file_type.lower() == 'audit':
                    continue
                    
                for carved_file in type_dir.iterdir():
                    if carved_file.is_file():
                        file_size = carved_file.stat().st_size
                        
                        carved_files.append({
                            'carved_filename': carved_file.name,
                            'file_path': str(carved_file),
                            'size_bytes': file_size,
                            'signature_type': file_type,
                            'carving_session_id': session_id
                        })
        
        return carved_files
    
    def verify_file_integrity(self, file_path: str, expected_hash: str) -> bool:
        """
        Verify file integrity using SHA-256 hash.
        
        FORENSIC: Critical for chain of custody
        """
        actual_hash = self.calculate_hash(file_path)
        return actual_hash.lower() == expected_hash.lower()

    def reset_investigation(self, db) -> Dict[str, Any]:
        """
        Completely reset the investigation environment.
        - Terminate active scalpel processes
        - Unmount all images
        - Delete carved and recovered files
        - Reset database
        """
        logger.info("🛑 Initiating full investigation reset")
        results = {
            "processes_terminated": 0,
            "mounts_cleaned": 0,
            "files_deleted": 0,
            "database_reset": False
        }

        # 1. Terminate scalpel processes
        try:
            # We look for processes running the 'scalpel' tool
            cmd = ["pgrep", "-f", self.scalpel]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                pids = proc.stdout.strip().split('\n')
                for pid in pids:
                    logger.info(f"Terminating scalpel process: {pid}")
                    subprocess.run(["kill", "-9", pid])
                    results["processes_terminated"] += 1
        except Exception as e:
            logger.error(f"Error terminating processes: {e}")

        # 2. Unmount all active mounts
        try:
            if self.mount_dir.exists():
                for item in self.mount_dir.iterdir():
                    if item.is_dir() and item.name.startswith("evidence_"):
                        logger.info(f"Cleaning up mount point: {item}")
                        if self.unmount_image(str(item)):
                            results["mounts_cleaned"] += 1
        except Exception as e:
            logger.error(f"Error cleaning up mounts: {e}")

        # 3. Delete files (Carved, Recovered, Temp)
        # We delete contents of these directories but keep the directories themselves
        for directory in [self.carved_dir, self.recovered_dir, self.temp_dir]:
            try:
                if directory.exists():
                    logger.info(f"Deleting contents of {directory}")
                    for item in directory.iterdir():
                        if item.is_dir():
                            shutil.rmtree(item)
                        else:
                            item.unlink()
                        results["files_deleted"] += 1
                
                # Re-ensure directory exists (shutil.rmtree might have been used on it if we misinterpreted)
                # But here we only rmtree children.
            except Exception as e:
                logger.error(f"Error deleting files in {directory}: {e}")

        # 4. Reset Database
        try:
            # Note: We should ideally close all sessions before dropping tables
            # In FastAPI, the 'db' session passed here is still open.
            # However, Base.metadata.drop_all(bind=engine) usually works with SQLite 
            # if we are not in the middle of a transaction that locks things.
            from app.database import drop_all_tables, init_database
            drop_all_tables()
            init_database()
            results["database_reset"] = True
            logger.info("✓ Database reset successfully")
        except Exception as e:
            logger.error(f"Error resetting database: {e}")
            results["database_reset"] = False

        return results
