#!/usr/bin/env python3
"""
Sequential upload of segmented E01 files.
Uploads each segment individually using the single-file endpoint,
then links them together as a segment set.
"""

import requests
from pathlib import Path
import sys
import time

# Configuration
API_BASE = "http://localhost:8000/api/v1/evidence"
EVIDENCE_DIR = "/mnt/hgfs/kali Share/evidence"
BASE_NAME = "Sample_18"

def upload_single_segment(file_path, case_name, examiner, case_number=None, description=None):
    """Upload a single E01 segment file"""
    
    with open(file_path, 'rb') as f:
        files = {
            'file': (file_path.name, f, 'application/octet-stream')
        }
        
        data = {
            'case_name': case_name,
            'examiner': examiner
        }
        
        if case_number:
            data['case_number'] = case_number
        if description:
            data['description'] = description
        
        try:
            print(f"   ⏳ Uploading {file_path.name}...")
            start_time = time.time()
            
            response = requests.post(
                f"{API_BASE}/upload",
                files=files,
                data=data,
                timeout=3600  # 1 hour timeout
            )
            
            elapsed = time.time() - start_time
            
            if response.status_code in [200, 201]:
                result = response.json()
                size_mb = file_path.stat().st_size / (1024 * 1024)
                speed = size_mb / elapsed if elapsed > 0 else 0
                print(f"   ✅ Uploaded in {elapsed:.1f}s ({speed:.1f} MB/s)")
                print(f"      ID: {result['evidence']['id']}, Hash: {result['evidence']['sha256_hash'][:16]}...")
                return result['evidence']
            else:
                print(f"   ❌ Failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return None


def upload_segments_sequentially():
    """Upload all segments one by one"""
    
    # Find all segment files
    evidence_path = Path(EVIDENCE_DIR)
    segment_files = sorted(evidence_path.glob(f"{BASE_NAME}.E*"))
    
    if not segment_files:
        print(f"❌ No segment files found matching {BASE_NAME}.E* in {EVIDENCE_DIR}")
        return False
    
    print(f"\n📁 Found {len(segment_files)} segment files:")
    total_size = 0
    for seg in segment_files:
        size_mb = seg.stat().st_size / (1024 * 1024)
        total_size += seg.stat().st_size
        print(f"   - {seg.name} ({size_mb:.1f} MB)")
    
    total_gb = total_size / (1024 * 1024 * 1024)
    print(f"\n📊 Total size: {total_gb:.2f} GB")
    print(f"\n🚀 Starting sequential upload...\n")
    
    # Upload each segment
    uploaded_evidence = []
    for i, seg_path in enumerate(segment_files, 1):
        print(f"\n[{i}/{len(segment_files)}] Processing {seg_path.name}")
        
        evidence = upload_single_segment(
            seg_path,
            case_name=BASE_NAME,
            examiner='Kali User',
            case_number='CASE-001',
            description=f'{BASE_NAME} evidence - Segment {i} of {len(segment_files)}'
        )
        
        if evidence:
            uploaded_evidence.append(evidence)
        else:
            print(f"\n❌ Upload failed for {seg_path.name}")
            print(f"   Stopping upload process.")
            return False
    
    # All segments uploaded successfully
    print(f"\n{'='*60}")
    print(f"✅ ALL SEGMENTS UPLOADED SUCCESSFULLY!")
    print(f"{'='*60}")
    print(f"\n📋 Summary:")
    print(f"   Total segments: {len(uploaded_evidence)}")
    print(f"   Total size: {total_gb:.2f} GB")
    print(f"\n🔍 Evidence IDs:")
    for ev in uploaded_evidence:
        print(f"   - ID {ev['id']}: {ev['filename']} ({ev['segment_number']} of {ev.get('total_segments', '?')})")
    
    return True


if __name__ == "__main__":
    print("\n" + "="*60)
    print("SEQUENTIAL E01 SEGMENT UPLOAD")
    print("="*60)
    
    # Check if server is running
    try:
        response = requests.get(f"{API_BASE}/list", timeout=5)
        if response.status_code != 200:
            print(f"\n❌ Server not responding correctly")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Cannot connect to server: {e}")
        print(f"   Ensure backend is running at http://localhost:8000")
        sys.exit(1)
    
    # Upload
    success = upload_segments_sequentially()
    
    if success:
        print(f"\n✅ Upload complete! You can now use these evidence files for analysis.")
    else:
        print(f"\n❌ Upload failed.")
    
    sys.exit(0 if success else 1)
