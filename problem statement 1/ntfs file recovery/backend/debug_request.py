#!/usr/bin/env python3
"""
Debug script to test upload-segments endpoint and see actual error messages.
"""

import requests
import tempfile
from pathlib import Path

API_BASE_URL = "http://localhost:8000/api/v1/evidence"


def create_test_files():
    """Create small test E01 files"""
    temp_dir = Path(tempfile.mkdtemp(prefix="debug_e01_"))
    files = []
    
    for i in range(1, 3):
        filename = f"test.E{i:02d}"
        file_path = temp_dir / filename
        
        with open(file_path, 'w') as f:
            f.write(f"Mock E01 segment {i}\n" * 10)
        
        files.append(file_path)
        print(f"Created: {filename}")
    
    return files, temp_dir


def test_upload_segments():
    """Test the upload-segments endpoint with verbose error output"""
    print("Creating test files...")
    segment_files, temp_dir = create_test_files()
    
    try:
        # Open files and prepare multipart form data
        files_list = []
        for seg_path in segment_files:
            files_list.append(
                ('files', (seg_path.name, open(seg_path, 'rb'), 'application/octet-stream'))
            )
        
        data = {
            'case_name': 'DEBUG_TEST',
            'examiner': 'Debug User'
        }
        
        print(f"\nSending POST request to {API_BASE_URL}/upload-segments")
        print(f"Data: {data}")
        print(f"Files: {[name for _, (name, _, _) in files_list]}")
        
        response = requests.post(
            f"{API_BASE_URL}/upload-segments",
            files=files_list,
            data=data,
            timeout=60
        )
        
        # Close file handles
        for _, (_, fh, _) in files_list:
            fh.close()
        
        print(f"\nResponse Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"\nResponse Body:")
        print(response.text)
        
        if response.status_code == 400:
            try:
                error_detail = response.json()
                print(f"\nError Detail (JSON):")
                print(f"  {error_detail}")
            except:
                pass
    
    except Exception as e:
        print(f"Exception occurred: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        import shutil
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up: {temp_dir}")


if __name__ == "__main__":
    test_upload_segments()
