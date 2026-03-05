#!/usr/bin/env python3
import sys
import os
from pathlib import Path
import yaml

# Add current directory to path so we can import app modules
sys.path.append(os.getcwd())

from app.services.segment_handler import SegmentHandler
from app.services.forensic_engine import ForensicEngine
from app.api.v1.evidence import get_db
from app.models import Evidence

def verify_segments_and_mount():
    # 1. Verify via SegmentHandler
    evidence_dir = Path("/home/kali/Desktop/project/ntfs pro/storage/evidence")
    base_name = "Sample_18_20260209_154226_Sample_18"
    
    print(f"Detecting segments for: {base_name}")
    segments = SegmentHandler.detect_segments_in_directory(evidence_dir, base_name)
    
    print(f"Found {len(segments)} segments.")
    for s in segments:
        print(f"  - {s.name}")
        
    validation = SegmentHandler.validate_segment_set(segments)
    print(f"Validation result: {validation['valid']}")
    if not validation['valid']:
        print(f"Missing segments: {validation['missing_segments']}")
        return
    
    # 2. Attempt to mount using ForensicEngine
    # Using ID 3 (the .E01 segment)
    engine = ForensicEngine()
    e01_path = str(evidence_dir / f"{base_name}.E01")
    
    print(f"\nAttempting to mount: {e01_path}")
    try:
        mount_point = engine.mount_image(e01_path, 3)
        print(f"✅ Successfully mounted at: {mount_point}")
        
        # 3. Detect partitions
        print("\nDetecting partitions...")
        partitions = engine.detect_partitions(mount_point)
        print(f"Found {len(partitions)} partitions:")
        for p in partitions:
            print(f"  Slot {p['slot']}: {p['filesystem_type']} at {p['start_offset']} ({p['size_bytes']} bytes)")
            
        return mount_point
    except Exception as e:
        print(f"❌ Failed to mount/scan: {e}")
        return None

if __name__ == "__main__":
    verify_segments_and_mount()
