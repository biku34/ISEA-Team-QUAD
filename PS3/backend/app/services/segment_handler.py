"""
Segment Handler - Utility for managing segmented E01 evidence files.
Handles detection, validation, and grouping of E01/E02/E03 file sets.

FORENSIC REQUIREMENTS:
- Detect all segments in a set
- Validate segment continuity
- Ensure complete set before processing
- Maintain segment order
"""

import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class SegmentError(Exception):
    """Error related to segmented evidence handling"""
    pass


class SegmentHandler:
    """
    Handles segmented E01 evidence files (E01, E02, E03, etc.)
    
    EnCase splits large disk images into multiple files with sequential extensions:
    - evidence.E01 (first segment)
    - evidence.E02 (second segment)
    - evidence.E03 (third segment)
    - ...
    
    All segments must be present for successful mounting and analysis.
    """
    
    # Pattern to match E01/E02/E03 etc. extensions
    SEGMENT_PATTERN = re.compile(r'^(.+)\.(E)(\d{2})$', re.IGNORECASE)
    
    @staticmethod
    def parse_segment_filename(filename: str) -> Optional[Tuple[str, int]]:
        """
        Parse segment filename to extract base name and segment number.
        
        Args:
            filename: File name to parse (e.g., "evidence.E01")
            
        Returns:
            Tuple of (base_name, segment_number) or None if not a segment file
            
        Examples:
            "evidence.E01" -> ("evidence", 1)
            "case123.e05" -> ("case123", 5)
            "disk.dd" -> None
        """
        match = SegmentHandler.SEGMENT_PATTERN.match(filename)
        if match:
            base_name = match.group(1)
            segment_num = int(match.group(3))
            return (base_name, segment_num)
        return None
    
    @staticmethod
    def is_segmented_file(filename: str) -> bool:
        """Check if filename represents a segmented evidence file"""
        return SegmentHandler.parse_segment_filename(filename) is not None
    
    @staticmethod
    def detect_segments_in_directory(directory: Path, base_name: str) -> List[Path]:
        """
        Detect all segments for a given base name in a directory.
        
        Args:
            directory: Directory to search
            base_name: Base name of the evidence (without extension)
            
        Returns:
            Sorted list of segment file paths
            
        Example:
            If directory contains: evidence.E01, evidence.E02, evidence.E03
            detect_segments_in_directory(dir, "evidence") -> [evidence.E01, evidence.E02, evidence.E03]
        """
        segments = []
        pattern = f"{base_name}.E*"
        
        for file_path in directory.glob(pattern):
            parsed = SegmentHandler.parse_segment_filename(file_path.name)
            if parsed and parsed[0].lower() == base_name.lower():
                segments.append((parsed[1], file_path))
        
        # Sort by segment number
        segments.sort(key=lambda x: x[0])
        
        return [path for _, path in segments]
    
    @staticmethod
    def validate_segment_set(segments: List[Path]) -> Dict[str, any]:
        """
        Validate that a set of segments is complete and properly ordered.
        
        Args:
            segments: List of segment file paths (should be sorted)
            
        Returns:
            Dictionary with validation results:
            {
                'valid': bool,
                'total_segments': int,
                'missing_segments': List[int],
                'total_size': int,
                'segments': List[Dict]
            }
            
        Raises:
            SegmentError: If validation fails critically
        """
        if not segments:
            raise SegmentError("No segments provided")
        
        # Parse all segments
        parsed_segments = []
        for seg_path in segments:
            parsed = SegmentHandler.parse_segment_filename(seg_path.name)
            if not parsed:
                raise SegmentError(f"Invalid segment filename: {seg_path.name}")
            
            base_name, seg_num = parsed
            
            # Check file exists and get size
            if not seg_path.exists():
                raise SegmentError(f"Segment file not found: {seg_path}")
            
            size = seg_path.stat().st_size
            parsed_segments.append({
                'path': seg_path,
                'base_name': base_name,
                'segment_number': seg_num,
                'size_bytes': size
            })
        
        # Sort by segment number
        parsed_segments.sort(key=lambda x: x['segment_number'])
        
        # Validate sequence starts at 1
        first_seg = parsed_segments[0]['segment_number']
        if first_seg != 1:
            raise SegmentError(f"First segment should be .E01, found .E{first_seg:02d}")
        
        # Check for gaps in sequence
        expected_nums = set(range(1, len(parsed_segments) + 1))
        actual_nums = set(seg['segment_number'] for seg in parsed_segments)
        missing = sorted(expected_nums - actual_nums)
        
        # Calculate total size
        total_size = sum(seg['size_bytes'] for seg in parsed_segments)
        
        # Validate base names are consistent
        base_names = set(seg['base_name'].lower() for seg in parsed_segments)
        if len(base_names) > 1:
            raise SegmentError(f"Inconsistent base names: {base_names}")
        
        valid = len(missing) == 0
        
        return {
            'valid': valid,
            'total_segments': len(parsed_segments),
            'missing_segments': missing,
            'total_size': total_size,
            'base_name': parsed_segments[0]['base_name'],
            'segments': parsed_segments
        }
    
    @staticmethod
    def get_primary_segment(segments: List[Path]) -> Path:
        """
        Get the primary segment (.E01) from a list of segments.
        
        Args:
            segments: List of segment paths
            
        Returns:
            Path to .E01 file
            
        Raises:
            SegmentError: If .E01 not found
        """
        for seg_path in segments:
            parsed = SegmentHandler.parse_segment_filename(seg_path.name)
            if parsed and parsed[1] == 1:
                return seg_path
        
        raise SegmentError("Primary segment (.E01) not found")
    
    @staticmethod
    def group_segments_by_base(directory: Path) -> Dict[str, List[Path]]:
        """
        Group all E01 files in a directory by their base name.
        
        Args:
            directory: Directory containing evidence files
            
        Returns:
            Dictionary mapping base_name -> list of segment paths
            
        Example:
            {
                'evidence1': [evidence1.E01, evidence1.E02],
                'case2': [case2.E01, case2.E02, case2.E03]
            }
        """
        groups = {}
        
        for file_path in directory.glob("*.E*"):
            parsed = SegmentHandler.parse_segment_filename(file_path.name)
            if parsed:
                base_name, seg_num = parsed
                
                if base_name not in groups:
                    groups[base_name] = []
                
                groups[base_name].append(file_path)
        
        # Sort each group by segment number
        for base_name in groups:
            segments = groups[base_name]
            segments.sort(key=lambda p: SegmentHandler.parse_segment_filename(p.name)[1])
        
        return groups
