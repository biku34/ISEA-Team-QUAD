#!/usr/bin/env python3
"""
Test script for segmented E01 file upload functionality.
Creates mock E01 segment files and tests the upload and validation.
"""

import requests
import os
from pathlib import Path
import tempfile
import shutil


API_BASE_URL = "http://localhost:8000/api/v1/evidence"


def create_mock_segment_files(base_name: str, num_segments: int) -> list:
    """
    Create mock E01 segment files for testing.
    
    Args:
        base_name: Base name for the evidence (e.g., "test_disk")
        num_segments: Number of segments to create
        
    Returns:
        List of file paths
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="e01_test_"))
    segment_files = []
    
    # Create mock segment files
    for i in range(1, num_segments + 1):
        filename = f"{base_name}.E{i:02d}"
        file_path = temp_dir / filename
        
        # Write some mock data (simulating E01 content)
        # In reality, E01 files have a specific format, but for testing upload logic this is fine
        mock_data = f"MOCK E01 SEGMENT {i}\n" * 100
        mock_data += f"Base: {base_name}\n"
        mock_data += f"Segment: {i} of {num_segments}\n"
        
        with open(file_path, 'w') as f:
            f.write(mock_data)
        
        segment_files.append(file_path)
        print(f"Created mock segment: {filename} ({file_path.stat().st_size} bytes)")
    
    return segment_files, temp_dir


def test_single_segment_upload():
    """Test uploading a single E01 file"""
    print("\n" + "="*60)
    print("TEST 1: Single E01 File Upload")
    print("="*60)
    
    # Create a single mock E01 file
    segments, temp_dir = create_mock_segment_files("single_test", 1)
    
    try:
        with open(segments[0], 'rb') as f:
            files = {'file': (segments[0].name, f, 'application/octet-stream')}
            data = {
                'case_name': 'TEST_SINGLE',
                'examiner': 'Test User',
                'case_number': 'CASE-001',
                'organization': 'Test Lab',
                'description': 'Single E01 file upload test'
            }
            
            response = requests.post(f"{API_BASE_URL}/upload", files=files, data=data)
            
            print(f"\nResponse Status: {response.status_code}")
            if response.status_code in [200, 201]:
                result = response.json()
                print(f"✓ Upload successful!")
                print(f"  Evidence ID: {result['evidence']['id']}")
                print(f"  Filename: {result['evidence']['filename']}")
                print(f"  Is Segmented: {result['evidence']['is_segmented']}")
                print(f"  Segment Number: {result['evidence']['segment_number']}")
                print(f"  Total Segments: {result['evidence']['total_segments']}")
                print(f"  SHA-256: {result['evidence']['sha256_hash'][:16]}...")
            else:
                print(f"✗ Upload failed: {response.text}")
    
    finally:
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up temp directory: {temp_dir}")


def test_multi_segment_upload():
    """Test uploading multiple E01 segments"""
    print("\n" + "="*60)
    print("TEST 2: Multi-Segment E01 Upload")
    print("="*60)
    
    # Create 3 mock segment files
    segments, temp_dir = create_mock_segment_files("multi_test", 3)
    
    try:
        # Prepare files for upload
        files = []
        for seg_path in segments:
            files.append(
                ('files', (seg_path.name, open(seg_path, 'rb'), 'application/octet-stream'))
            )
        
        data = {
            'case_name': 'TEST_MULTI',
            'examiner': 'Test User',
            'case_number': 'CASE-002',
            'organization': 'Test Lab',
            'description': 'Multi-segment E01 upload test (3 segments)'
        }
        
        response = requests.post(f"{API_BASE_URL}/upload-segments", files=files, data=data)
        
        # Close file handles
        for _, (_, fh, _) in files:
            fh.close()
        
        print(f"\nResponse Status: {response.status_code}")
        if response.status_code in [200, 201]:
            result = response.json()
            print(f"✓ Upload successful!")
            print(f"  Message: {result['message']}")
            print(f"  Evidence ID: {result['evidence']['id']}")
            print(f"  Filename: {result['evidence']['filename']}")
            print(f"  Is Segmented: {result['evidence']['is_segmented']}")
            print(f"  Total Segments: {result['evidence']['total_segments']}")
            print(f"  Total Size: {result['segment_info']['total_size']} bytes")
            print(f"\n  Segment Details:")
            for seg in result['segment_info']['segments']:
                print(f"    - Segment {seg['segment_number']}: {seg['filename']}")
                print(f"      Size: {seg['size_bytes']} bytes")
                print(f"      SHA-256: {seg['sha256_hash'][:16]}...")
        else:
            print(f"✗ Upload failed: {response.text}")
    
    finally:
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up temp directory: {temp_dir}")


def test_incomplete_segment_set():
    """Test uploading an incomplete segment set (should fail)"""
    print("\n" + "="*60)
    print("TEST 3: Incomplete Segment Set (Should Fail)")
    print("="*60)
    
    # Create 3 segments but only upload 2 (skip E02)
    segments, temp_dir = create_mock_segment_files("incomplete_test", 3)
    
    try:
        # Only upload E01 and E03 (missing E02)
        files = [
            ('files', (segments[0].name, open(segments[0], 'rb'), 'application/octet-stream')),
            ('files', (segments[2].name, open(segments[2], 'rb'), 'application/octet-stream'))
        ]
        
        data = {
            'case_name': 'TEST_INCOMPLETE',
            'examiner': 'Test User',
            'description': 'Incomplete segment set - should fail'
        }
        
        response = requests.post(f"{API_BASE_URL}/upload-segments", files=files, data=data)
        
        # Close file handles
        for _, (_, fh, _) in files:
            fh.close()
        
        print(f"\nResponse Status: {response.status_code}")
        if response.status_code == 400:
            print(f"✓ Correctly rejected incomplete segment set")
            print(f"  Error: {response.json()['detail']}")
        else:
            print(f"✗ Unexpected response: {response.text}")
    
    finally:
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up temp directory: {temp_dir}")


def test_list_evidence():
    """Test listing all evidence"""
    print("\n" + "="*60)
    print("TEST 4: List All Evidence")
    print("="*60)
    
    response = requests.get(f"{API_BASE_URL}/list")
    
    if response.status_code == 200:
        result = response.json()
        print(f"✓ Retrieved {result['total']} evidence items")
        print(f"\nEvidence List:")
        for evidence in result['evidence']:
            seg_info = ""
            if evidence.get('is_segmented'):
                seg_info = f" (Segmented: {evidence.get('total_segments')} segments)"
            print(f"  - ID {evidence['id']}: {evidence['case_name']} - {evidence['filename']}{seg_info}")
    else:
        print(f"✗ Failed to retrieve evidence list: {response.text}")


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("SEGMENTED E01 FILE UPLOAD TESTS")
    print("="*60)
    print(f"API Base URL: {API_BASE_URL}")
    
    # Check if server is running
    try:
        response = requests.get(f"{API_BASE_URL}/list")
        if response.status_code != 200:
            print(f"\n✗ Server is not responding correctly. Please ensure the backend is running.")
            print(f"  Start server with: uvicorn app.main:app --reload")
            return
    except Exception as e:
        print(f"\n✗ Cannot connect to server: {e}")
        print(f"  Please ensure the backend is running at {API_BASE_URL}")
        return
    
    # Run tests
    test_single_segment_upload()
    test_multi_segment_upload()
    test_incomplete_segment_set()
    test_list_evidence()
    
    print("\n" + "="*60)
    print("TESTS COMPLETED")
    print("="*60)


if __name__ == "__main__":
    main()
