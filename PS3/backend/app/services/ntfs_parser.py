"""
NTFS Parser — Phase 2: Data Collection Layer.

Reads the six Phase-1 extracted binary artifacts and builds four
in-memory data structures needed by the wipe detection engine:

    cluster_history_map  — {cluster: {file_reference, filename, timestamps}}
    allocation_map       — {cluster: True/False}
    usn_map              — {file_reference: [{reason, timestamp}]}
    logfile_events       — {cluster: [event_strings]}   (optional)

All parsing is done in pure Python with the struct / mmap modules for
efficiency — no external libraries required.

Forensic design notes
─────────────────────
• We never write to the artifact files (read-only file handles).
• Malformed records are skipped with a warning; partial data is returned.
• All cluster numbers are 0-based.
"""

from __future__ import annotations

import struct
import mmap
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from loguru import logger


# ═══════════════════════════════════════════════════════════════════════════
# NTFS on-disk constants
# ═══════════════════════════════════════════════════════════════════════════

MFT_ENTRY_SIZE          = 1024          # Standard MFT record size (bytes)
MFT_SIGNATURE           = b"FILE"       # Valid MFT entry magic

# Attribute type codes
ATTR_STANDARD_INFO      = 0x10          # $STANDARD_INFORMATION
ATTR_FILE_NAME          = 0x30          # $FILE_NAME
ATTR_DATA               = 0x80          # $DATA

# $STANDARD_INFORMATION offsets (relative to attribute content start)
SI_CREATED_OFF   = 0                    # 8 bytes FILETIME
SI_MODIFIED_OFF  = 8
SI_MFT_CHGD_OFF  = 16
SI_ACCESSED_OFF  = 24

# $FILE_NAME attribute content offsets
FN_PARENT_OFF    = 0                    # 8 bytes (MFT ref + seq)
FN_CREATED_OFF   = 8
FN_MODIFIED_OFF  = 16
FN_MFT_CHGD_OFF  = 24
FN_ACCESSED_OFF  = 32
FN_ALLOC_SIZE_OFF = 40
FN_REAL_SIZE_OFF  = 48
FN_FLAGS_OFF      = 56
FN_REPARSE_OFF    = 60
FN_NAME_LEN_OFF   = 64                  # 1 byte: number of UTF-16 chars
FN_NAME_NS_OFF    = 65                  # 1 byte: namespace (0=POSIX,1=Win32,2=DOS,3=Win32&DOS)
FN_NAME_OFF       = 66                  # UTF-16LE name starts here

# MFT entry header offsets
MFT_HDR_UPD_OFF  = 4                    # 2 bytes: update sequence offset
MFT_HDR_UPD_CNT  = 6                    # 2 bytes: update sequence count
MFT_HDR_LOGFILE  = 8                    # 8 bytes: $LogFile LSN
MFT_HDR_SEQ      = 16                   # 2 bytes: sequence number
MFT_HDR_LINK_CNT = 18                   # 2 bytes: link count
MFT_HDR_ATTR_OFF = 20                   # 2 bytes: offset to first attribute
MFT_HDR_FLAGS    = 22                   # 2 bytes: 0x01=allocated, 0x02=directory
MFT_HDR_USED     = 24                   # 4 bytes: used bytes in record
MFT_HDR_ALLOC    = 28                   # 4 bytes: allocated bytes for record
MFT_HDR_BASE_REF = 32                   # 8 bytes: base MFT ref (0 = this is base)

# Attribute header offsets (resident and non-resident share first 16 bytes)
ATTR_TYPE_OFF    = 0                    # 4 bytes
ATTR_LEN_OFF     = 4                    # 4 bytes
ATTR_NR_OFF      = 8                    # 1 byte: 0=resident, 1=non-resident
ATTR_NAME_LEN    = 9                    # 1 byte: name length (UTF-16 chars)
ATTR_FLAGS_OFF   = 12                   # 2 bytes
ATTR_INST_OFF    = 14                   # 2 bytes: attribute instance

# Resident attribute extras
ATTR_RES_SIZE_OFF  = 16                 # 4 bytes: value length
ATTR_RES_VOFF_OFF  = 20                 # 2 bytes: value offset

# Non-resident attribute extras
ATTR_NR_START_VCN  = 16                 # 8 bytes: starting VCN
ATTR_NR_LAST_VCN   = 24                 # 8 bytes: last VCN
ATTR_NR_RL_OFF     = 32                 # 2 bytes: runlist offset
ATTR_NR_COMPUNIT   = 34                 # 2 bytes: compression unit
ATTR_NR_ALLOC_SIZE = 40                 # 8 bytes: allocated size
ATTR_NR_DATA_SIZE  = 48                 # 8 bytes: real data size

# USN Journal record V2
USN_V2_RECLEN_OFF   = 0                 # 4 bytes
USN_V2_MAJVER_OFF   = 4                 # 2 bytes
USN_V2_MINVER_OFF   = 6                 # 2 bytes
USN_V2_FILEREF_OFF  = 8                 # 8 bytes
USN_V2_PARENTREF_OFF = 16              # 8 bytes
USN_V2_USN_OFF      = 24               # 8 bytes (USN)
USN_V2_TIMESTAMP_OFF = 32              # 8 bytes (FILETIME)
USN_V2_REASON_OFF   = 40               # 4 bytes
USN_V2_SRCINFO_OFF  = 44               # 4 bytes
USN_V2_SECID_OFF    = 48               # 4 bytes
USN_V2_FILEATTR_OFF = 52               # 4 bytes
USN_V2_NAMELEN_OFF  = 56               # 2 bytes (bytes, not chars)
USN_V2_NAMEOFF_OFF  = 58               # 2 bytes
USN_V2_MIN_SIZE     = 60               # Minimum V2 record size

# USN Reason flags (important subset)
USN_REASON = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00100000: "BASIC_INFO_CHANGE",
    0x80000000: "CLOSE",
}

# Wipe-relevant USN reason flags
WIPE_RELEVANT_REASONS = {
    "DATA_OVERWRITE",
    "DATA_TRUNCATION",
    "FILE_DELETE",
    "DATA_EXTEND",
}

# FILETIME epoch offset (100-nanosecond intervals from 1601-01-01)
FILETIME_EPOCH_DELTA = 116444736000000000  # 100-ns intervals


def filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convert Windows FILETIME (100-ns intervals since 1601) to UTC datetime."""
    if ft == 0:
        return None
    try:
        us = (ft - FILETIME_EPOCH_DELTA) // 10  # microseconds since Unix epoch
        return datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
# NTFSParser
# ═══════════════════════════════════════════════════════════════════════════

class NTFSParser:
    """
    Parses extracted NTFS artifact files (Phase 1 output) into data maps
    consumed by the wipe detection engine (Phase 3).

    All public methods accept the path to the extracted binary artifact
    and return the corresponding data map dict.
    """

    # ────────────────────────────────────────────────────────────────────────
    # §1  $Boot — read cluster geometry
    # ────────────────────────────────────────────────────────────────────────

    def parse_boot(self, boot_path: str) -> Dict[str, int]:
        """
        Parse $Boot (VBR) to extract volume geometry.

        Returns:
            {
              "bytes_per_sector":    512,
              "sectors_per_cluster": 8,
              "bytes_per_cluster":   4096,
              "total_sectors":       ...,
              "mft_cluster":         ...,   # logical cluster of $MFT
              "mft_mirror_cluster":  ...,
            }
        """
        path = Path(boot_path)
        if not path.exists() or path.stat().st_size < 512:
            logger.warning(f"[Phase2] $Boot file missing or too small: {boot_path}")
            return {}

        with open(path, "rb") as f:
            vbr = f.read(512)

        # NTFS VBR layout:
        # 0x03: OEM ID ("NTFS    ")
        # 0x0B: bytes per sector       (2 bytes LE)
        # 0x0D: sectors per cluster    (1 byte)
        # 0x28: total sectors          (8 bytes LE)
        # 0x30: MFT LCN               (8 bytes LE)
        # 0x38: MFT mirror LCN        (8 bytes LE)

        if vbr[3:11] != b"NTFS    ":
            logger.warning("[Phase2] $Boot OEM ID is not 'NTFS    ' — not an NTFS VBR")
            return {}

        bps  = struct.unpack_from("<H", vbr, 0x0B)[0]
        spc  = struct.unpack_from("<B", vbr, 0x0D)[0]
        total_sectors = struct.unpack_from("<Q", vbr, 0x28)[0]
        mft_lcn       = struct.unpack_from("<Q", vbr, 0x30)[0]
        mft_mir_lcn   = struct.unpack_from("<Q", vbr, 0x38)[0]

        bpc = bps * spc

        geometry = {
            "bytes_per_sector":    bps,
            "sectors_per_cluster": spc,
            "bytes_per_cluster":   bpc,
            "total_sectors":       total_sectors,
            "total_clusters":      total_sectors // spc if spc else 0,
            "mft_cluster":         mft_lcn,
            "mft_mirror_cluster":  mft_mir_lcn,
        }
        logger.info(
            f"[Phase2] $Boot: {bps}B/sector, {spc}sec/cluster → {bpc}B/cluster, "
            f"{geometry['total_clusters']:,} total clusters, MFT@LCN {mft_lcn}"
        )
        return geometry

    # ────────────────────────────────────────────────────────────────────────
    # §2  $Bitmap — cluster allocation map
    # ────────────────────────────────────────────────────────────────────────

    def parse_bitmap(self, bitmap_path: str) -> Tuple[Dict[int, bool], int]:
        """
        Parse $Bitmap into a per-cluster allocation dict.

        Returns:
            (allocation_map, highest_allocated_cluster)

            allocation_map = { cluster_number: True (allocated) / False (free) }
        """
        path = Path(bitmap_path)
        if not path.exists():
            logger.error(f"[Phase2] $Bitmap file not found: {bitmap_path}")
            return {}, -1

        allocation_map: Dict[int, bool] = {}
        highest = -1
        cluster = 0

        logger.info(f"[Phase2] Parsing $Bitmap ({path.stat().st_size:,} bytes)...")

        with open(path, "rb") as f:
            for byte_val in iter(lambda: f.read(1), b""):
                b = byte_val[0]
                for bit in range(8):
                    allocated = bool((b >> bit) & 1)
                    allocation_map[cluster] = allocated
                    if allocated:
                        highest = cluster
                    cluster += 1

        logger.info(
            f"[Phase2] $Bitmap parsed: {cluster:,} clusters, "
            f"{sum(allocation_map.values()):,} allocated, "
            f"highest allocated cluster: {highest:,}"
        )
        return allocation_map, highest

    # ────────────────────────────────────────────────────────────────────────
    # §3  $MFT — cluster history map
    # ────────────────────────────────────────────────────────────────────────

    def parse_mft(
        self,
        mft_path: str,
        bytes_per_cluster: int = 4096,
    ) -> Dict[int, Dict]:
        """
        Parse $MFT to build the cluster ownership history map.

        For each valid FILE record we decode:
          • $FILE_NAME  → filename + namespace
          • $STANDARD_INFORMATION → MACB timestamps
          • $DATA (non-resident) → runlist → cluster numbers

        Returns:
            cluster_history_map = {
                cluster_number: {
                    "file_reference": mft_entry_number,
                    "filename": str,
                    "allocated": bool,          # MFT flag: file is allocated
                    "timestamps": {
                        "created", "modified", "accessed", "mft_changed"
                    }
                }
            }
        """
        path = Path(mft_path)
        if not path.exists():
            logger.error(f"[Phase2] $MFT file not found: {mft_path}")
            return {}

        file_size = path.stat().st_size
        num_entries = file_size // MFT_ENTRY_SIZE
        logger.info(
            f"[Phase2] Parsing $MFT ({file_size:,} bytes, "
            f"~{num_entries:,} entries)..."
        )

        cluster_history_map: Dict[int, Dict] = {}
        parsed = 0
        skipped = 0

        with open(path, "rb") as f:
            for entry_idx in range(num_entries):
                raw = f.read(MFT_ENTRY_SIZE)
                if len(raw) < MFT_ENTRY_SIZE:
                    break

                info = self._parse_mft_entry(raw, entry_idx, bytes_per_cluster)
                if info is None:
                    skipped += 1
                    continue

                parsed += 1
                for cluster in info["clusters"]:
                    cluster_history_map[cluster] = {
                        "file_reference": entry_idx,
                        "filename":       info["filename"],
                        "allocated":      info["is_allocated"],
                        "timestamps":     info["timestamps"],
                    }

        logger.info(
            f"[Phase2] $MFT: parsed {parsed:,} entries, "
            f"skipped {skipped:,}, "
            f"mapped {len(cluster_history_map):,} clusters"
        )
        return cluster_history_map

    def _parse_mft_entry(
        self, raw: bytes, entry_idx: int, bytes_per_cluster: int
    ) -> Optional[Dict]:
        """Return parsed MFT entry info dict or None if invalid/empty."""
        if len(raw) < 48:
            return None
        if raw[:4] != MFT_SIGNATURE:
            return None   # not a valid FILE record

        # Apply update sequence fixup
        raw = bytearray(raw)
        usn_off = struct.unpack_from("<H", raw, 4)[0]
        usn_cnt = struct.unpack_from("<H", raw, 6)[0]  # includes USN itself
        if usn_off + usn_cnt * 2 > MFT_ENTRY_SIZE:
            return None
        usn_value = struct.unpack_from("<H", raw, usn_off)[0]
        for i in range(1, usn_cnt):
            sector_end = i * 512 - 2
            if sector_end + 2 > MFT_ENTRY_SIZE:
                break
            raw[sector_end]     = raw[usn_off + i * 2]
            raw[sector_end + 1] = raw[usn_off + i * 2 + 1]

        flags      = struct.unpack_from("<H", raw, MFT_HDR_FLAGS)[0]
        is_alloc   = bool(flags & 0x01)
        attr_off   = struct.unpack_from("<H", raw, MFT_HDR_ATTR_OFF)[0]
        used_bytes = struct.unpack_from("<I", raw, MFT_HDR_USED)[0]

        filename   = ""
        timestamps = {}
        clusters: List[int] = []

        pos = attr_off
        while pos + 4 <= used_bytes and pos + 4 <= MFT_ENTRY_SIZE:
            attr_type = struct.unpack_from("<I", raw, pos)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack_from("<I", raw, pos + 4)[0]
            if attr_len < 8 or pos + attr_len > MFT_ENTRY_SIZE:
                break

            non_resident = raw[pos + 8]
            name_len_attr = raw[pos + 9]

            try:
                if attr_type == ATTR_STANDARD_INFO and not non_resident:
                    res_size = struct.unpack_from("<I", raw, pos + 16)[0]
                    val_off  = struct.unpack_from("<H", raw, pos + 20)[0]
                    vstart   = pos + val_off
                    if vstart + 32 <= pos + attr_len:
                        timestamps = {
                            "created":     filetime_to_datetime(
                                struct.unpack_from("<Q", raw, vstart + SI_CREATED_OFF)[0]),
                            "modified":    filetime_to_datetime(
                                struct.unpack_from("<Q", raw, vstart + SI_MODIFIED_OFF)[0]),
                            "mft_changed": filetime_to_datetime(
                                struct.unpack_from("<Q", raw, vstart + SI_MFT_CHGD_OFF)[0]),
                            "accessed":    filetime_to_datetime(
                                struct.unpack_from("<Q", raw, vstart + SI_ACCESSED_OFF)[0]),
                        }

                elif attr_type == ATTR_FILE_NAME and not non_resident:
                    val_off = struct.unpack_from("<H", raw, pos + 20)[0]
                    vstart  = pos + val_off
                    if vstart + 66 <= pos + attr_len:
                        namespace   = raw[vstart + FN_NAME_NS_OFF]
                        name_len_c  = raw[vstart + FN_NAME_LEN_OFF]
                        name_bytes  = bytes(raw[vstart + FN_NAME_OFF:
                                                vstart + FN_NAME_OFF + name_len_c * 2])
                        # Prefer Win32 or Win32&DOS namespace (skip DOS-only)
                        if namespace in (1, 3) or not filename:
                            filename = name_bytes.decode("utf-16-le", errors="replace")

                elif attr_type == ATTR_DATA and non_resident:
                    # Only parse unnamed $DATA streams (name_len == 0)
                    if name_len_attr == 0:
                        rl_off = struct.unpack_from("<H", raw, pos + 32)[0]
                        rl_start = pos + rl_off
                        if rl_start < pos + attr_len:
                            clusters = self._decode_runlist(
                                bytes(raw[rl_start: pos + attr_len])
                            )

            except (struct.error, UnicodeDecodeError, IndexError):
                pass   # skip malformed attribute, continue to next

            pos += attr_len

        # Only track entries with cluster data (skips sparse/resident-only)
        if not clusters:
            return None

        return {
            "filename":    filename or f"<MFT:{entry_idx}>",
            "is_allocated": is_alloc,
            "timestamps":  timestamps,
            "clusters":    clusters,
        }

    def _decode_runlist(self, data: bytes) -> List[int]:
        """
        Decode an NTFS runlist (data runs) into a flat list of LCNs.

        Runlist encoding:
          byte  header: low nibble = length-field bytes, high nibble = offset-field bytes
          If header == 0x00 → end of runlist
          length field (LE signed int): run length in clusters
          offset field (LE signed int): relative LCN delta from previous run
        """
        clusters: List[int] = []
        pos = 0
        current_lcn = 0

        while pos < len(data):
            header = data[pos]
            if header == 0:
                break
            pos += 1

            len_bytes = header & 0x0F
            off_bytes = (header >> 4) & 0x0F

            if pos + len_bytes + off_bytes > len(data):
                break

            # Unsigned run length
            run_len_raw = data[pos: pos + len_bytes]
            run_len = int.from_bytes(run_len_raw, "little", signed=False)
            pos += len_bytes

            # Signed LCN delta
            if off_bytes:
                delta_raw = data[pos: pos + off_bytes]
                # Sign-extend
                delta = int.from_bytes(delta_raw, "little", signed=True)
                pos += off_bytes
                current_lcn += delta
            # else: sparse run (delta == 0, LCN stays 0 or uninitialised)

            # Expand: add every cluster in this run
            # Cap expansion to avoid OOM on corrupt data
            cap = min(run_len, 10_000_000)
            for c in range(current_lcn, current_lcn + cap):
                clusters.append(c)

        return clusters

    # ────────────────────────────────────────────────────────────────────────
    # §4  $UsnJrnl:$J — USN change journal
    # ────────────────────────────────────────────────────────────────────────

    def parse_usn_journal(self, usn_path: str) -> Dict[int, List[Dict]]:
        """
        Parse $UsnJrnl:$J binary dump into a file_reference → events map.

        Handles:
          • Leading zero-filled pages (journal sparse regions)
          • USN_RECORD_V2 (major version 2)
          • USN_RECORD_V3 (major version 3, 128-bit file reference) — skipped
            gracefully (not commonly encountered)

        Returns:
            usn_map = {
                file_reference_number: [
                    {
                        "reason":    "DATA_OVERWRITE",
                        "timestamp": datetime,
                        "usn":       int,
                        "filename":  str,
                        "parent_ref": int,
                    },
                    ...
                ]
            }
        """
        path = Path(usn_path)
        if not path.exists():
            logger.error(f"[Phase2] $UsnJrnl:$J file not found: {usn_path}")
            return {}

        file_size = path.stat().st_size
        if file_size == 0:
            logger.warning("[Phase2] $UsnJrnl:$J is empty — journal may be inactive")
            return {}

        logger.info(f"[Phase2] Parsing $UsnJrnl:$J ({file_size:,} bytes)...")

        usn_map: Dict[int, List[Dict]] = {}
        records_parsed = 0
        pos = 0

        with open(path, "rb") as f:
            data = f.read()

        while pos < len(data):
            # Skip zero-filled pages (sparse journal regions)
            if data[pos: pos + 4] == b"\x00\x00\x00\x00":
                # Jump ahead to next 4KB page boundary
                next_page = (pos + 4096) & ~4095
                pos = next_page
                continue

            if pos + USN_V2_MIN_SIZE > len(data):
                break

            rec_len = struct.unpack_from("<I", data, pos + USN_V2_RECLEN_OFF)[0]
            if rec_len < USN_V2_MIN_SIZE or rec_len > 65536:
                # Corrupt record — advance 8 bytes and re-scan
                pos += 8
                continue

            maj_ver = struct.unpack_from("<H", data, pos + USN_V2_MAJVER_OFF)[0]
            if maj_ver != 2:
                # V3 uses 128-bit file refs; skip for now
                pos += rec_len
                continue

            if pos + rec_len > len(data):
                break

            try:
                file_ref  = struct.unpack_from("<Q", data, pos + USN_V2_FILEREF_OFF)[0]
                par_ref   = struct.unpack_from("<Q", data, pos + USN_V2_PARENTREF_OFF)[0]
                usn       = struct.unpack_from("<Q", data, pos + USN_V2_USN_OFF)[0]
                filetime  = struct.unpack_from("<Q", data, pos + USN_V2_TIMESTAMP_OFF)[0]
                reason    = struct.unpack_from("<I", data, pos + USN_V2_REASON_OFF)[0]
                name_len  = struct.unpack_from("<H", data, pos + USN_V2_NAMELEN_OFF)[0]
                name_off  = struct.unpack_from("<H", data, pos + USN_V2_NAMEOFF_OFF)[0]

                name_start = pos + name_off
                name_end   = name_start + name_len
                filename = ""
                if name_start < pos + rec_len and name_end <= pos + rec_len:
                    filename = data[name_start:name_end].decode("utf-16-le", errors="replace")

                ts = filetime_to_datetime(filetime)

                # Decode reason flags
                reason_strs = [
                    label for flag, label in USN_REASON.items()
                    if reason & flag
                ]

                # Strip sequence number from file reference (low 48 bits = MFT entry)
                mft_entry = file_ref & 0x0000FFFFFFFFFFFF

                event = {
                    "reason":     ", ".join(reason_strs) if reason_strs else f"0x{reason:08X}",
                    "reason_flags": reason_strs,
                    "timestamp":  ts,
                    "usn":        usn,
                    "filename":   filename,
                    "parent_ref": par_ref & 0x0000FFFFFFFFFFFF,
                }

                if mft_entry not in usn_map:
                    usn_map[mft_entry] = []
                usn_map[mft_entry].append(event)
                records_parsed += 1

            except struct.error:
                pos += 8
                continue

            pos += rec_len

        logger.info(
            f"[Phase2] $UsnJrnl:$J parsed: {records_parsed:,} records, "
            f"{len(usn_map):,} unique file references"
        )
        return usn_map

    # ────────────────────────────────────────────────────────────────────────
    # §5  $LogFile — transaction event map (optional)
    # ────────────────────────────────────────────────────────────────────────

    def parse_logfile(self, logfile_path: str) -> Dict[int, List[str]]:
        """
        Parse $LogFile LSN (Log Sequence Number) entries to detect
        cluster deallocation transactions.

        The NTFS $LogFile is a circular transaction log with a complex
        format. This implementation performs a heuristic scan for NTFS
        log record headers (signature 0x44524352 / "RCRD") and extracts
        redo/undo operation codes that indicate bitmap modifications
        (cluster allocations / deallocations).

        Redo/Undo op codes related to bitmap changes:
          0x05 = SetBitsInNonResidentBitMap   (allocate)
          0x06 = ClearBitsInNonResidentBitMap (deallocate / wipe)

        Note: This is heuristic — for full LCN accuracy a complete
        multi-pass LSN walker would be required. Even this partial
        analysis adds valuable corroboration.

        Returns:
            logfile_events = {
                cluster_number: ["DEALLOCATED", ...]
            }
        """
        path = Path(logfile_path)
        if not path.exists():
            logger.warning(f"[Phase2] $LogFile not found: {logfile_path}")
            return {}

        file_size = path.stat().st_size
        logger.info(f"[Phase2] Scanning $LogFile ({file_size:,} bytes) for deallocation ops...")

        RCRD_SIG   = b"RCRD"
        PAGE_SIZE  = 4096
        # Op code for ClearBitsInNonResidentBitMap
        OP_CLEAR   = 0x0006

        logfile_events: Dict[int, List[str]] = {}
        pages_found = 0

        with open(path, "rb") as f:
            data = f.read()

        pos = 0
        while pos + PAGE_SIZE <= len(data):
            page = data[pos: pos + PAGE_SIZE]

            # Check page signature
            if page[:4] != RCRD_SIG:
                pos += PAGE_SIZE
                continue

            pages_found += 1
            # Scan the page for log records
            # Each log record has a 0x28-byte header preceded by op codes
            # We do a simplified scan: look for OP_CLEAR in 2-byte LE values
            inner = 0x28  # skip page header
            while inner + 8 <= PAGE_SIZE:
                try:
                    op_code = struct.unpack_from("<H", page, inner)[0]
                    if op_code == OP_CLEAR:
                        # Try to read target cluster from nearby data
                        # In practice the cluster number appears 8 bytes
                        # after the op code in many record types
                        if inner + 16 <= PAGE_SIZE:
                            cluster_candidate = struct.unpack_from("<Q", page, inner + 8)[0]
                            # Sanity: plausible cluster number (< 1 billion)
                            if 0 < cluster_candidate < 1_000_000_000:
                                if cluster_candidate not in logfile_events:
                                    logfile_events[cluster_candidate] = []
                                if "DEALLOCATED" not in logfile_events[cluster_candidate]:
                                    logfile_events[cluster_candidate].append("DEALLOCATED")
                except struct.error:
                    pass
                inner += 4

            pos += PAGE_SIZE

        logger.info(
            f"[Phase2] $LogFile: {pages_found} RCRD pages, "
            f"{len(logfile_events)} deallocation events found"
        )
        return logfile_events

    # ────────────────────────────────────────────────────────────────────────
    # §6  Convenience: parse all artifacts at once
    # ────────────────────────────────────────────────────────────────────────

    def parse_all(
        self,
        mft_path:     str,
        bitmap_path:  str,
        usn_path:     str,
        logfile_path: str,
        boot_path:    str,
    ) -> Dict[str, Any]:
        """
        Parse all Phase-1 artifacts and return the complete data collection layer.

        Returns:
            {
              "geometry":           {bytes_per_cluster, total_clusters, ...},
              "allocation_map":     {cluster: bool},
              "highest_allocated":  int,
              "cluster_history_map":{cluster: {file_reference, filename, ...}},
              "usn_map":            {mft_entry: [{reason, timestamp, ...}]},
              "logfile_events":     {cluster: [event_strings]},
            }
        """
        logger.info("[Phase2] Starting full artifact parse pass...")

        geometry = self.parse_boot(boot_path)
        bpc = geometry.get("bytes_per_cluster", 4096)

        allocation_map, highest = self.parse_bitmap(bitmap_path)
        cluster_history_map     = self.parse_mft(mft_path, bpc)
        usn_map                 = self.parse_usn_journal(usn_path)
        logfile_events          = self.parse_logfile(logfile_path)

        result = {
            "geometry":            geometry,
            "allocation_map":      allocation_map,
            "highest_allocated":   highest,
            "cluster_history_map": cluster_history_map,
            "usn_map":             usn_map,
            "logfile_events":      logfile_events,
        }

        logger.info(
            "[Phase2] Parse complete — "
            f"clusters mapped: {len(allocation_map):,}, "
            f"history entries: {len(cluster_history_map):,}, "
            f"USN file refs: {len(usn_map):,}, "
            f"logfile events: {len(logfile_events):,}"
        )
        return result

    # ────────────────────────────────────────────────────────────────────────
    # §7  Helper: get USN events for a cluster (via cluster_history_map lookup)
    # ────────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_usn_events_for_cluster(
        cluster: int,
        cluster_history_map: Dict[int, Dict],
        usn_map: Dict[int, List[Dict]],
    ) -> List[Dict]:
        """
        Convenience: resolve cluster → file_reference → USN events.
        """
        entry = cluster_history_map.get(cluster)
        if not entry:
            return []
        file_ref = entry.get("file_reference")
        if file_ref is None:
            return []
        return usn_map.get(file_ref, [])
