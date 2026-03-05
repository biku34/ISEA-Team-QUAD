"""
$LogFile Binary Parser
======================
Parses raw NTFS $LogFile (inode 2) binary to extract:

  - Global LSN range  : [lsn_min, lsn_max] across all valid RCRD pages
  - Per-inode events  : dict[inode -> list[(lsn, wall_clock_ts_or_None, op_code)]]
ntfs pro/app/services/antiforensics_engines/logfile_parser.py
NTFS $LogFile layout
--------------------
  The file consists of 4096-byte pages:
    - Pages 0-1   : RSTR  (restart area, "RSTR" signature)
    - Pages 2+    : RCRD  (log record pages, "RCRD" signature)

  Each RCRD page header (48 bytes):
    Offset  Size  Field
    0       4     Signature   "RCRD"
    4       2     Update-sequence array offset
    6       2     Update-sequence array count
    8       8     Last LSN on this page
    16      2     Flags
    18      2     Page count
    20      2     Page position
    40      8     File reference (when page is part of a restart record — unused)

  Log records are packed after the RCRD header.  Each log record:
    Offset  Size  Field
    0       2     Reserved / type
    2       2     Flags
    4       2     Undo op
    6       2     Redo op
    8       8     This LSN
    16      8     Previous LSN
    24      8     Undo next LSN
    32      4     Data length
    36      2     Undo data length
    ...
    48      8     MFT file reference (inode:seq packed as 6-byte inode + 2-byte seq LE)
    56      8     MFT parent reference

  Redo/Undo op codes of interest — NTFS_LOG_OPERATION:
    0x00 = Noop / End
    0x02 = InitializeFileRecordSegment  (file create)
    0x03 = DeallocateFileRecordSegment  (file delete)
    0x05 = CreateAttribute / SetNewAttributeValue  ($SI set on create)
    0x06 = DeleteAttribute
    0x07 = UpdateResidentValue  ($SI attribute write — $LogFile equivalent
           of SetBasicInformation.  When redo_len >= 32 and payload starts
           with four valid FILETIMEs, this is a "Set Basic Information" op.)
    0x08 = UpdateNonresidentValue
    0x0B = SetNewAttributeSizes
    0x11 = SetIndexEntryVcnAllocation
    0x13 = UpdateFileNameRoot  ($FN timestamp update)
    0x14 = UpdateFileNameAllocation
    0x18 = CommitTransaction   (transaction boundary — no file ref)
    0x19 = ForgetTransaction
    0x1F = DeleteAttribute
    0x21 = OpenAttribute (always present when attribute is opened for update)

NOTE: $LogFile does NOT store wall-clock timestamps inside log records itself.
Wall-clock time is embedded only when an UpdateResidentValue / SetNewAttributeValue
record writes a $STANDARD_INFORMATION attribute payload (80-byte struct whose first
32 bytes are four 8-byte FILETIME values).  We attempt to parse those.

This parser is defensive — any malformed page / record is silently skipped.
"""

from __future__ import annotations

import struct
import datetime
import os
from typing import Dict, List, Optional, Tuple

# Constants
PAGE_SIZE = 4096
RSTR_SIG = b"RSTR"
RCRD_SIG = b"RCRD"
LR_HEADER_SIZE = 58  # bytes before variable-length redo/undo data

# Op-codes that touch $STANDARD_INFORMATION (attribute type 0x10 = 16)
_SI_OPS = {0x05, 0x07}  # CreateAttribute / SetNewAttributeValue, UpdateResidentValue
_SET_BASIC_INFO_OP = 0x07

# NTFS FILETIME epoch: 1601-01-01 00:00:00 UTC  →  Unix epoch offset
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
_100NS_PER_SEC = 10_000_000

def _filetime_to_dt(raw: int) -> Optional[datetime.datetime]:
    """Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to UTC datetime."""
    if raw == 0 or raw > 0x7FFF_FFFF_FFFF_FFFF:
        return None
    try:
        seconds = raw / _100NS_PER_SEC
        return _FILETIME_EPOCH + datetime.timedelta(seconds=seconds)
    except (OverflowError, OSError):
        return None

def _apply_usa(page: bytearray, usa_offset: int, usa_count: int) -> bytearray:
    """
    Apply Update Sequence Array fixup in-place.
    Each sector (512 bytes) ends with USA value; replace with saved original.
    usa_count includes the sequence number itself — actual replacements = usa_count - 1.
    """
    if usa_count < 2 or usa_offset + usa_count * 2 > len(page):
        return page
    # stored usa[0] = sequence number (verification tag)
    seq = struct.unpack_from("<H", page, usa_offset)[0]
    for i in range(1, usa_count):
        sector_end = i * 512 - 2
        if sector_end + 2 > len(page):
            break
        page[sector_end] = page[usa_offset + i * 2]
        page[sector_end + 1] = page[usa_offset + i * 2 + 1]
    return page

class LogFileEvent:
    """One log record that touched a specific MFT inode."""
    __slots__ = ("inode", "lsn", "redo_op", "undo_op", "si_timestamps", "is_set_basic_info")

    def __init__(
        self,
        inode: int,
        lsn: int,
        redo_op: int,
        undo_op: int,
        si_timestamps: Optional[List[datetime.datetime]] = None,
        is_set_basic_info: bool = False,
    ):
        self.inode = inode
        self.lsn = lsn
        self.redo_op = redo_op
        self.undo_op = undo_op
        # If record carried a $SI payload, these are the parsed MACB datetimes
        self.si_timestamps: List[datetime.datetime] = si_timestamps or []
        # True when this is an UpdateResidentValue op that wrote a $SI FILETIME block
        # — $LogFile equivalent of a "SetBasicInformation" call
        self.is_set_basic_info: bool = is_set_basic_info

class LogFileSummary:
    """Aggregate result from parsing $LogFile."""

    def __init__(self):
        self.lsn_min: int = 0
        self.lsn_max: int = 0
        self.pages_parsed: int = 0
        self.records_parsed: int = 0
        # inode → list of LogFileEvent (sorted by LSN ascending)
        self.events_by_inode: Dict[int, List[LogFileEvent]] = {}

    def all_si_timestamps_for_inode(self, inode: int) -> List[datetime.datetime]:
        """Return all $SI-embedded timestamps seen in $LogFile for a given inode."""
        events = self.events_by_inode.get(inode, [])
        result = []
        for ev in events:
            result.extend(ev.si_timestamps)
        return result

    def first_si_timestamp_for_inode(self, inode: int) -> Optional[datetime.datetime]:
        """
        Return the earliest $SI FILETIME extracted from $LogFile for this inode.
        This is the "first $LogFile TransactionTime" for that file — when used
        against $SI.create it provides a Transaction Inversion check.
        """
        all_ts = self.all_si_timestamps_for_inode(inode)
        if not all_ts:
            return None
        return min(all_ts)

    def set_basic_info_count_for_inode(self, inode: int) -> int:
        """
        Return the number of $LogFile records that are identified as
        'SetBasicInformation' ops (UpdateResidentValue writing $SI FILETIME block)
        for the given inode.
        """
        return sum(
            1 for ev in self.events_by_inode.get(inode, [])
            if ev.is_set_basic_info
        )

    def lsn_range_for_inode(self, inode: int) -> Tuple[int, int]:
        """Return (min_lsn, max_lsn) seen for that inode, or (0,0)."""
        events = self.events_by_inode.get(inode, [])
        if not events:
            return (0, 0)
        lsns = [e.lsn for e in events]
        return (min(lsns), max(lsns))

def parse_logfile(data: bytes) -> LogFileSummary:
    """
    Parse a raw $LogFile binary blob and return a LogFileSummary.

    Args:
        data: raw bytes of extracted $LogFile (typically 4-64 MB)

    Returns:
        LogFileSummary with lsn_min, lsn_max, events_by_inode populated.
    """
    summary = LogFileSummary()
    lsn_min = 2**63
    lsn_max = 0
    n_pages = len(data) // PAGE_SIZE

    for page_idx in range(n_pages):
        offset = page_idx * PAGE_SIZE
        raw_page = bytearray(data[offset: offset + PAGE_SIZE])

        sig = bytes(raw_page[:4])
        if sig not in (RCRD_SIG, RSTR_SIG):
            continue
        if sig == RSTR_SIG:
            continue  # Restart areas don't carry log records

        # Parse RCRD header
        try:
            usa_off = struct.unpack_from("<H", raw_page, 4)[0]
            usa_cnt = struct.unpack_from("<H", raw_page, 6)[0]
            page_lsn = struct.unpack_from("<Q", raw_page, 8)[0]
        except struct.error:
            continue

        # Apply USA fixup so sector tail bytes are correct
        raw_page = _apply_usa(raw_page, usa_off, usa_cnt)

        if page_lsn > 0:
            lsn_min = min(lsn_min, page_lsn)
            lsn_max = max(lsn_max, page_lsn)

        summary.pages_parsed += 1

        # Walk log records starting at offset 48 (after RCRD header)
        rec_off = 48
        while rec_off + LR_HEADER_SIZE <= PAGE_SIZE:
            try:
                rec_lsn = struct.unpack_from("<Q", raw_page, rec_off + 8)[0]
                if rec_lsn == 0:
                    break  # end sentinel

                undo_op = struct.unpack_from("<H", raw_page, rec_off + 4)[0]
                redo_op = struct.unpack_from("<H", raw_page, rec_off + 6)[0]
                redo_len = struct.unpack_from("<I", raw_page, rec_off + 32)[0]
                undo_len = struct.unpack_from("<H", raw_page, rec_off + 36)[0]
                
                # Dynamic offsets for redo/undo data
                redo_op_off = struct.unpack_from("<H", raw_page, rec_off + 40)[0]

                # File reference at offset +48 relative to record start
                # Lower 6 bytes = inode number (LE), upper 2 bytes = seq
                file_ref_raw = struct.unpack_from("<Q", raw_page, rec_off + 48)[0]
                inode = file_ref_raw & 0x0000_FFFF_FFFF_FFFF
                # Filter out meta-file inodes (0–11) and obviously bad values
                valid_inode = 12 <= inode < 0x0000_FFFF_FFFF_0000

                lsn_min = min(lsn_min, rec_lsn)
                lsn_max = max(lsn_max, rec_lsn)
                summary.records_parsed += 1

                # Try to parse embedded $SI payload from redo data
                si_timestamps: List[datetime.datetime] = []
                if valid_inode and redo_op in _SI_OPS and redo_len >= 72 and redo_op_off >= 48:
                    payload_off = rec_off + redo_op_off
                    if payload_off + 32 <= PAGE_SIZE:
                        # Try to read four FILETIMEs (32 bytes)
                        ft_values = struct.unpack_from("<4Q", raw_page, payload_off)
                        parsed = [_filetime_to_dt(ft) for ft in ft_values]
                        # Only accept if at least 2 look like sane modern timestamps
                        sane = [
                            dt for dt in parsed
                            if dt and datetime.datetime(1990, 1, 1, tzinfo=datetime.timezone.utc) < dt <
                               datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc)
                        ]
                        if len(sane) >= 2:
                            si_timestamps = sane

                if valid_inode:
                    is_sbi = (
                        redo_op == _SET_BASIC_INFO_OP
                        and len(si_timestamps) >= 2  # confirmed $SI FILETIME payload
                    )
                    ev = LogFileEvent(
                        inode=inode,
                        lsn=rec_lsn,
                        redo_op=redo_op,
                        undo_op=undo_op,
                        si_timestamps=si_timestamps,
                        is_set_basic_info=is_sbi,
                    )
                    summary.events_by_inode.setdefault(inode, []).append(ev)

                # Advance: fixed header (58) + redo_len + undo_len, aligned to 8 bytes
                total_rec = LR_HEADER_SIZE + redo_len + undo_len
                total_rec = (total_rec + 7) & ~7  # 8-byte alignment
                if total_rec < LR_HEADER_SIZE:
                    break  # safety
                rec_off += max(total_rec, LR_HEADER_SIZE)

            except struct.error:
                break

    summary.lsn_min = lsn_min if lsn_max > 0 else 0
    summary.lsn_max = lsn_max

    # Sort events per inode by LSN
    for inode_events in summary.events_by_inode.values():
        inode_events.sort(key=lambda e: e.lsn)

    return summary

def load_and_parse_logfile(path: str) -> LogFileSummary:
    """Convenience: read file from disk and parse."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) < PAGE_SIZE:
            print(f"[LogFileParser] $LogFile too small ({len(data)} bytes) — skipping.")
            return LogFileSummary()
        return parse_logfile(data)
    except OSError as exc:
        print(f"[LogFileParser] Cannot read $LogFile at {path}: {exc}")
        return LogFileSummary()

def analyze_tampering(logfile_path: str) -> Dict:
    """
    Parse $LogFile and analyze for timestamp tampering evidence
    """
    try:
        summary = load_and_parse_logfile(logfile_path)
        
        # Analyze for tampering evidence
        evidence = []
        high_risk_indicators = []
        
        for inode, events in summary.events_by_inode.items():
            if len(events) < 2:
                continue  # Need at least 2 events to detect tampering
                
            # Look for suspicious patterns
            for i in range(1, len(events)):
                current = events[i]
                previous = events[i-1]
                
                # Check for rapid timestamp changes
                if current.si_timestamps and previous.si_timestamps:
                    # Use modification time (second timestamp in $SI block)
                    if len(current.si_timestamps) >= 2 and len(previous.si_timestamps) >= 2:
                        current_mod = current.si_timestamps[1]  # Modification time
                        previous_mod = previous.si_timestamps[1]  # Modification time
                        
                        time_diff = abs((current_mod - previous_mod).total_seconds())
                        
                        # If timestamps changed significantly in short LSN distance
                        lsn_diff = current.lsn - previous.lsn
                        if lsn_diff < 1000 and time_diff > 3600:  # Less than 1000 LSNs but more than 1 hour
                            evidence_item = {
                                'inode': inode,
                                'type': 'rapid_timestamp_change',
                                'severity': 'high',
                                'description': f'Rapid timestamp modification detected for inode {inode}',
                                'events': [
                                    {
                                        'lsn': previous.lsn,
                                        'operation': 'SetBasicInformation' if previous.is_set_basic_info else 'Other',
                                        'timestamps': [ts.isoformat() for ts in previous.si_timestamps]
                                    },
                                    {
                                        'lsn': current.lsn,
                                        'operation': 'SetBasicInformation' if current.is_set_basic_info else 'Other',
                                        'timestamps': [ts.isoformat() for ts in current.si_timestamps]
                                    }
                                ],
                                'time_difference': {
                                    'seconds': time_diff,
                                    'lsn_difference': lsn_diff
                                }
                            }
                            evidence.append(evidence_item)
                            high_risk_indicators.append(evidence_item)
                    
                    # Check for impossible timestamps (e.g., modification before creation)
                    if len(current.si_timestamps) >= 4:
                        creation = current.si_timestamps[0]  # Creation time
                        modification = current.si_timestamps[1]  # Modification time
                        
                        if modification < creation:
                            evidence_item = {
                                'inode': inode,
                                'type': 'impossible_timestamp',
                                'severity': 'high',
                                'description': f'Modification time before creation time for inode {inode}',
                                'events': [
                                    {
                                        'lsn': current.lsn,
                                        'operation': 'SetBasicInformation' if current.is_set_basic_info else 'Other',
                                        'timestamps': [ts.isoformat() for ts in current.si_timestamps]
                                    }
                                ],
                                'timestamps': {
                                    'creation_time': creation.isoformat(),
                                    'modification_time': modification.isoformat()
                                }
                            }
                            evidence.append(evidence_item)
                            high_risk_indicators.append(evidence_item)
        
        # Convert events to serializable format
        serializable_events = {}
        for inode, events in summary.events_by_inode.items():
            serializable_events[str(inode)] = [
                {
                    'lsn': ev.lsn,
                    'redo_op': ev.redo_op,
                    'undo_op': ev.undo_op,
                    'si_timestamps': [ts.isoformat() for ts in ev.si_timestamps],
                    'is_set_basic_info': ev.is_set_basic_info
                }
                for ev in events
            ]
        
        return {
            'total_pages': summary.pages_parsed,
            'total_records': summary.records_parsed,
            'inode_count': len(summary.events_by_inode),
            'lsn_min': summary.lsn_min,
            'lsn_max': summary.lsn_max,
            'events_by_inode': serializable_events,
            'tampering_evidence': evidence,
            'evidence_count': len(evidence),
            'high_risk_indicators': high_risk_indicators,
            'parsing_timestamp': datetime.datetime.now().isoformat()
        }
        
    except Exception as e:
        raise Exception(f"Failed to analyze logfile: {str(e)}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python logfile_parser.py <logfile_path>")
        sys.exit(1)
        
    logfile_path = sys.argv[1]
    
    if not os.path.exists(logfile_path):
        print(f"Error: File {logfile_path} not found")
        sys.exit(1)
    
    print(f"Parsing $LogFile: {logfile_path}")
    
    try:
        results = analyze_tampering(logfile_path)
        
        print(f"\n=== $LogFile Analysis Results ===")
        print(f"Total Pages: {results['total_pages']}")
        print(f"Total Records: {results['total_records']}")
        print(f"Inodes Modified: {results['inode_count']}")
        print(f"LSN Range: [{results['lsn_min']}, {results['lsn_max']}]")
        print(f"Tampering Evidence: {results['evidence_count']}")
        print(f"High Risk Indicators: {len(results['high_risk_indicators'])}")
        
        if results['tampering_evidence']:
            print(f"\n=== Tampering Evidence ===")
            for i, evidence in enumerate(results['tampering_evidence'], 1):
                print(f"\n{i}. {evidence['description']}")
                print(f"   Type: {evidence['type']}")
                print(f"   Severity: {evidence['severity']}")
                print(f"   Inode: {evidence['inode']}")
        
        # Save detailed results
        output_file = logfile_path + '_analysis.json'
        import json
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\nDetailed results saved to: {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
