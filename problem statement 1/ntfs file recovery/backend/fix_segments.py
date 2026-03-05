#!/usr/bin/env python3
import sqlite3
import os
from pathlib import Path

# Configuration
DB_PATH = "/home/kali/Desktop/project/ntfs pro/forensic_recovery.db"
EVIDENCE_DIR = "/home/kali/Desktop/project/ntfs pro/storage/evidence"
MASTER_TIMESTAMP = "20260209_154226"
CASE_NAME = "Sample_18"
BASE_NAME = "Sample_18"

def fix_grouping():
    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get all segments for Sample_18
    cursor.execute("SELECT id, filename, file_path, segment_number FROM evidence WHERE case_name = ?", (CASE_NAME,))
    segments = cursor.fetchall()
    
    print(f"Found {len(segments)} segments to process.")
    
    total_segments = len(segments)
    
    for segment_id, old_filename, old_path, seg_num in segments:
        ext = f"E{seg_num:02d}"
        new_filename = f"{CASE_NAME}_{MASTER_TIMESTAMP}_{BASE_NAME}.{ext}"
        new_path = f"storage/evidence/{new_filename}"
        
        full_old_path = Path("/home/kali/Desktop/project/ntfs pro") / old_path
        full_new_path = Path("/home/kali/Desktop/project/ntfs pro") / new_path
        
        print(f"Processing ID {segment_id}:")
        print(f"  Old: {old_filename}")
        print(f"  New: {new_filename}")
        
        # Rename file if it exists and path has changed
        if full_old_path != full_new_path:
            if full_old_path.exists():
                print(f"  Renaming file...")
                full_old_path.rename(full_new_path)
            else:
                print(f"  Warning: Old file not found: {full_old_path}")
        
        # Update database
        cursor.execute("""
            UPDATE evidence 
            SET filename = ?, 
                file_path = ?, 
                total_segments = ?,
                is_segmented = 1
            WHERE id = ?
        """, (new_filename, new_path, total_segments, segment_id))
        
    conn.commit()
    conn.close()
    print("\nSuccessfully synchronized segments and updated database.")

if __name__ == "__main__":
    fix_grouping()
