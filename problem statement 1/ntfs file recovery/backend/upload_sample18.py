#!/usr/bin/env python3
"""
Upload segmented E01 files to the backend.
This script properly handles large file uploads using the requests library.
"""

import requests
from pathlib import Path
import sys

# Configuration
API_URL = "http://localhost:8000/api/v1/evidence/upload-segments"
EVIDENCE_DIR = "/mnt/hgfs/kali Share/evidence"
BASE_NAME = "Sample_18"

def upload_segments():
    """Upload all Sample_18 segments to the backend"""
    
    # Find all segment files
    evidence_path = Path(EVIDENCE_DIR)
    segment_files = sorted(evidence_path.glob(f"{BASE_NAME}.E*"))
    
    if not segment_files:
        print(f"❌ No segment files found matching {BASE_NAME}.E* in {EVIDENCE_DIR}")
        return False
    
    print(f"📁 Found {len(segment_files)} segment files:")
    for seg in segment_files:
        size_mb = seg.stat().st_size / (1024 * 1024)
        print(f"   - {seg.name} ({size_mb:.1f} MB)")
    
    total_size = sum(seg.stat().st_size for seg in segment_files)
    total_gb = total_size / (1024 * 1024 * 1024)
    print(f"\n📊 Total size: {total_gb:.2f} GB")
    print(f"\n⏳ Starting upload... This may take several minutes.\n")
    
    # Prepare the multipart form data
    # IMPORTANT: Don't open all files at once for large files
    files_to_upload = []
    file_handles = []
    
    try:
        for seg_path in segment_files:
            fh = open(seg_path, 'rb')
            file_handles.append(fh)
            files_to_upload.append(
                ('files', (seg_path.name, fh, 'application/octet-stream'))
            )
        
        # Form data
        data = {
            'case_name': BASE_NAME,
            'examiner': 'Kali User',
            'case_number': 'CASE-001',
            'description': f'{BASE_NAME} evidence - {len(segment_files)} segments'
        }
        
        # Upload with a long timeout
        print(f"🚀 Uploading to {API_URL}...")
        response = requests.post(
            API_URL,
            files=files_to_upload,
            data=data,
            timeout=3600  # 1 hour timeout for large uploads
        )
        
        # Check response
        if response.status_code in [200, 201]:
            print(f"\n✅ Upload successful!")
            result = response.json()
            print(f"\n📋 Evidence Details:")
            print(f"   ID: {result['evidence']['id']}")
            print(f"   Case: {result['evidence']['case_name']}")
            print(f"   Segments: {result['evidence']['total_segments']}")
            print(f"   Total Size: {result['segment_info']['total_size']:,} bytes")
            print(f"\n🔐 Segment Hashes:")
            for seg_info in result['segment_info']['segments']:
                print(f"   Segment {seg_info['segment_number']}: {seg_info['sha256_hash'][:16]}...")
            return True
        else:
            print(f"\n❌ Upload failed!")
            print(f"   Status Code: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print(f"\n❌ Upload timed out! The files might be too large or the network too slow.")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"\n❌ Connection error: {e}")
        print(f"   Make sure the backend server is running at http://localhost:8000")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Clean up file handles
        for fh in file_handles:
            try:
                fh.close()
            except:
                pass

if __name__ == "__main__":
    success = upload_segments()
    sys.exit(0 if success else 1)
