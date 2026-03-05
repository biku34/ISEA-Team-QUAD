#!/usr/bin/env python3
"""
Python client example for NTFS Forensic Recovery System API.
Demonstrates programmatic access to all API endpoints.

Requirements:
    pip install requests
"""

import requests
import json
import time
from pathlib import Path
from typing import Dict, List, Optional


class ForensicRecoveryClient:
    """
    Python client for NTFS Forensic Recovery System API.
    
    Usage:
        client = ForensicRecoveryClient("http://localhost:8000")
        evidence_id = client.upload_evidence("case.E01", "CASE-2024-001", "John Doe")
        partitions = client.scan_partitions(evidence_id)
    """
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize client with API base URL"""
        self.base_url = base_url
        self.api_url = f"{base_url}/api/v1"
        self.session = requests.Session()
    
    def upload_evidence(
        self,
        file_path: str,
        case_name: str,
        examiner: str,
        case_number: Optional[str] = None,
        expected_hash: Optional[str] = None
    ) -> Dict:
        """
        Upload E01 evidence file.
        
        Args:
            file_path: Path to E01 file
            case_name: Case identifier
            examiner: Examiner name
            case_number: Optional case number
            expected_hash: Optional SHA-256 hash for verification
        
        Returns:
            Evidence metadata including ID
        """
        url = f"{self.api_url}/evidence/upload"
        
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {
                'case_name': case_name,
                'examiner': examiner,
            }
            
            if case_number:
                data['case_number'] = case_number
            
            if expected_hash:
                data['expected_hash'] = expected_hash
            
            response = self.session.post(url, files=files, data=data)
            response.raise_for_status()
            
            return response.json()
    
    def verify_evidence(self, evidence_id: int, expected_hash: str) -> Dict:
        """Verify evidence integrity"""
        url = f"{self.api_url}/evidence/verify/{evidence_id}"
        
        response = self.session.post(url, json={'expected_hash': expected_hash})
        response.raise_for_status()
        
        return response.json()
    
    def list_evidence(self, case_name: Optional[str] = None) -> Dict:
        """List all evidence files"""
        url = f"{self.api_url}/evidence/list"
        params = {}
        
        if case_name:
            params['case_name'] = case_name
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def scan_partitions(self, evidence_id: int) -> Dict:
        """Scan for partitions using mmls"""
        url = f"{self.api_url}/scan/partitions"
        
        response = self.session.post(url, json={'evidence_id': evidence_id})
        response.raise_for_status()
        
        return response.json()
    
    def scan_deleted_files(self, evidence_id: int, partition_id: int) -> Dict:
        """Scan for deleted files using fls"""
        url = f"{self.api_url}/scan/deleted"
        
        response = self.session.post(
            url,
            json={'evidence_id': evidence_id, 'partition_id': partition_id}
        )
        response.raise_for_status()
        
        return response.json()
    
    def get_deleted_files(
        self,
        partition_id: int,
        file_type: Optional[str] = None,
        limit: int = 100
    ) -> Dict:
        """Get list of deleted files"""
        url = f"{self.api_url}/scan/deleted/{partition_id}"
        params = {'limit': limit}
        
        if file_type:
            params['file_type'] = file_type
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def recover_file(self, deleted_file_id: int) -> Dict:
        """Recover a specific deleted file using icat"""
        url = f"{self.api_url}/recovery/recover/{deleted_file_id}"
        
        response = self.session.post(url)
        response.raise_for_status()
        
        return response.json()
    
    def carve_files(self, evidence_id: int, partition_id: int) -> Dict:
        """Carve files from unallocated space using Scalpel"""
        url = f"{self.api_url}/recovery/carve"
        
        response = self.session.post(
            url,
            json={'evidence_id': evidence_id, 'partition_id': partition_id}
        )
        response.raise_for_status()
        
        return response.json()
    
    def generate_timeline(self, evidence_id: int) -> Dict:
        """Generate MACB timeline"""
        url = f"{self.api_url}/forensics/timeline/{evidence_id}"
        
        response = self.session.get(url)
        response.raise_for_status()
        
        return response.json()
    
    def get_file_metadata(self, deleted_file_id: int) -> Dict:
        """Get complete MFT metadata for a deleted file"""
        url = f"{self.api_url}/forensics/metadata/{deleted_file_id}"
        
        response = self.session.get(url)
        response.raise_for_status()
        
        return response.json()
    
    def get_audit_log(
        self,
        evidence_id: Optional[int] = None,
        action: Optional[str] = None,
        limit: int = 100
    ) -> Dict:
        """Get audit log entries"""
        url = f"{self.api_url}/forensics/audit/log"
        params = {'limit': limit}
        
        if evidence_id:
            params['evidence_id'] = evidence_id
        
        if action:
            params['action'] = action
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def generate_report(self, evidence_id: int, format: str = "json") -> Dict:
        """Generate forensic report"""
        url = f"{self.api_url}/forensics/report/generate"
        
        response = self.session.post(
            url,
            json={'evidence_id': evidence_id, 'format': format}
        )
        response.raise_for_status()
        
        return response.json()
    
    def download_recovered_file(self, file_id: int, output_path: str):
        """Download a recovered file"""
        url = f"{self.api_url}/files/download/recovered/{file_id}"
        
        response = self.session.get(url, stream=True)
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Get hash from header
        sha256 = response.headers.get('X-File-SHA256', 'unknown')
        return sha256
    
    def get_statistics(self, evidence_id: int) -> Dict:
        """Get analysis statistics"""
        url = f"{self.api_url}/forensics/statistics/{evidence_id}"
        
        response = self.session.get(url)
        response.raise_for_status()
        
        return response.json()


def main():
    """Example workflow using the Python client"""
    
    print("=" * 70)
    print("NTFS Forensic Recovery System - Python Client Example")
    print("=" * 70)
    
    # Initialize client
    client = ForensicRecoveryClient("http://localhost:8000")
    
    # Example workflow
    example_file = "./test_evidence.E01"
    
    if not Path(example_file).exists():
        print(f"\n⚠️  Example evidence file not found: {example_file}")
        print("Please provide a valid E01 file path to run this example.")
        return
    
    try:
        # Step 1: Upload evidence
        print("\n📤 Uploading evidence...")
        result = client.upload_evidence(
            file_path=example_file,
            case_name="EXAMPLE-2024-001",
            examiner="Python Client",
            expected_hash=None  # Set to actual hash if known
        )
        
        evidence_id = result['evidence']['id']
        print(f"✓ Evidence uploaded: ID={evidence_id}")
        print(f"  SHA-256: {result['evidence']['sha256_hash']}")
        
        # Step 2: Scan partitions
        print("\n🔍 Scanning partitions...")
        result = client.scan_partitions(evidence_id)
        
        partitions = result['partitions']
        print(f"✓ Found {len(partitions)} partitions")
        
        # Find NTFS partition
        ntfs_partition = next((p for p in partitions if p['is_ntfs']), None)
        
        if not ntfs_partition:
            print("⚠️  No NTFS partition found")
            return
        
        partition_id = ntfs_partition['id']
        print(f"  NTFS Partition: ID={partition_id}, Size={ntfs_partition['size_bytes']} bytes")
        
        # Step 3: Scan deleted files
        print("\n🗑️  Scanning for deleted files...")
        result = client.scan_deleted_files(evidence_id, partition_id)
        
        deleted_count = result['deleted_file_count']
        print(f"✓ Found {deleted_count} deleted files")
        
        if deleted_count == 0:
            print("No deleted files found.")
            return
        
        # Step 4: Get deleted files list
        print("\n📋 Retrieving deleted files list...")
        result = client.get_deleted_files(partition_id, limit=10)
        
        deleted_files = result['deleted_files']
        print(f"✓ Retrieved {len(deleted_files)} files (showing first 10)")
        
        for i, df in enumerate(deleted_files[:5], 1):
            print(f"  {i}. {df['filename']} ({df['size_bytes']} bytes, inode={df['inode']})")
        
        # Step 5: Recover first file
        if deleted_files:
            print("\n♻️  Recovering first deleted file...")
            first_file_id = deleted_files[0]['id']
            
            result = client.recover_file(first_file_id)
            
            recovered_file = result['recovered_file']
            print(f"✓ File recovered: {recovered_file['original_filename']}")
            print(f"  SHA-256: {recovered_file['sha256_hash']}")
            print(f"  Size: {recovered_file['size_bytes']} bytes")
        
        # Step 6: Generate timeline
        print("\n📅 Generating MACB timeline...")
        result = client.generate_timeline(evidence_id)
        
        timeline = result['timeline']
        print(f"✓ Generated timeline with {len(timeline)} events")
        
        if timeline:
            print("  Recent events:")
            for event in timeline[:3]:
                print(f"    {event['timestamp']} [{event['type']}] {event['description']}")
        
        # Step 7: Get statistics
        print("\n📊 Getting analysis statistics...")
        result = client.get_statistics(evidence_id)
        
        stats = result['statistics']
        print(f"✓ Analysis complete:")
        print(f"  Partitions: {stats['total_partitions']} ({stats['ntfs_partitions']} NTFS)")
        print(f"  Deleted files: {stats['total_deleted_files']}")
        print(f"  Recovered files: {stats['total_recovered_files']}")
        print(f"  Recovery rate: {stats['recovery_rate']}")
        
        # Step 8: Generate report
        print("\n📄 Generating forensic report...")
        result = client.generate_report(evidence_id, format="json")
        
        print(f"✓ Report generated: {result['report_path']}")
        
        print("\n" + "=" * 70)
        print("✅ Forensic analysis complete!")
        print("=" * 70)
    
    except requests.HTTPError as e:
        print(f"\n❌ API Error: {e}")
        print(f"Response: {e.response.text}")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
