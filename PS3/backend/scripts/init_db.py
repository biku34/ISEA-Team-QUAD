#!/usr/bin/env python3
"""
Database initialization script.
Creates all tables and sets up the database schema.

Usage:
    python scripts/init_db.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import init_database, drop_all_tables
import argparse


def main():
    parser = argparse.ArgumentParser(description="Initialize forensic recovery database")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop all existing tables before creating (WARNING: Data loss!)"
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("NTFS Forensic Recovery System - Database Initialization")
    print("=" * 70)
    
    if args.reset:
        print("\n⚠️  WARNING: This will DROP ALL EXISTING TABLES!")
        confirm = input("Type 'YES' to confirm: ")
        
        if confirm != "YES":
            print("Aborted.")
            return
        
        print("\n🗑️  Dropping all tables...")
        drop_all_tables()
    
    print("\n📊 Creating database tables...")
    init_database()
    
    print("\n✅ Database initialization complete!")
    print("\nCreated tables:")
    print("  - evidence")
    print("  - partitions")
    print("  - deleted_files")
    print("  - recovered_files")
    print("  - carved_files")
    print("  - audit_logs")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
