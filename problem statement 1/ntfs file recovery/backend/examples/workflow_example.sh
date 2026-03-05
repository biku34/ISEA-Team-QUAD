#!/bin/bash

# Example workflow for NTFS Forensic Recovery System
# This script demonstrates the complete forensic workflow using cURL

BASE_URL="http://localhost:8000/api/v1"

echo "========================================================================"
echo "NTFS Forensic Recovery System - Example Workflow"
echo "========================================================================"

# Configuration
EVIDENCE_FILE="./test_evidence.E01"
CASE_NAME="CASE-2024-001"
EXAMINER="John Doe"
EXPECTED_HASH="abc123..."  # Replace with actual hash

echo ""
echo "📋 Prerequisites:"
echo "  - Server running on http://localhost:8000"
echo "  - Evidence file available: $EVIDENCE_FILE"
echo ""

# Step 1: Upload Evidence
echo "========================================================================"
echo "Step 1: Upload E01 Evidence"
echo "========================================================================"

UPLOAD_CMD="curl -X POST \"$BASE_URL/evidence/upload\" \
  -F \"file=@$EVIDENCE_FILE\" \
  -F \"case_name=$CASE_NAME\" \
  -F \"examiner=$EXAMINER\" \
  -F \"expected_hash=$EXPECTED_HASH\""

echo "Command:"
echo "$UPLOAD_CMD"
echo ""
echo "Expected output: Evidence ID"
echo ""

# Uncomment to run:
# EVIDENCE_ID=$(eval $UPLOAD_CMD | jq -r '.evidence.id')
# echo "Evidence ID: $EVIDENCE_ID"

# For this example, we'll assume evidence_id=1
EVIDENCE_ID=1

echo ""
read -p "Press Enter to continue to Step 2..."

# Step 2: Verify Hash
echo ""
echo "========================================================================"
echo "Step 2: Verify Evidence Hash"
echo "========================================================================"

VERIFY_CMD="curl -X POST \"$BASE_URL/evidence/verify/$EVIDENCE_ID\" \
  -H \"Content-Type: application/json\" \
  -d '{\"expected_hash\": \"$EXPECTED_HASH\"}'"

echo "Command:"
echo "$VERIFY_CMD"
echo ""
echo "Expected output: Hash verification result"
echo ""

read -p "Press Enter to continue to Step 3..."

# Step 3: Scan Partitions
echo ""
echo "========================================================================"
echo "Step 3: Scan Partitions (mmls)"
echo "========================================================================"

SCAN_PARTITIONS_CMD="curl -X POST \"$BASE_URL/scan/partitions\" \
  -H \"Content-Type: application/json\" \
  -d '{\"evidence_id\": $EVIDENCE_ID}'"

echo "Command:"
echo "$SCAN_PARTITIONS_CMD"
echo ""
echo "Expected output: List of detected partitions"
echo ""

# Uncomment to run:
# PARTITION_ID=$(eval $SCAN_PARTITIONS_CMD | jq -r '.partitions[0].id')

# For this example, assume partition_id=1
PARTITION_ID=1

read -p "Press Enter to continue to Step 4..."

# Step 4: Scan Deleted Files
echo ""
echo "========================================================================"
echo "Step 4: Scan for Deleted Files (fls)"
echo "========================================================================"

SCAN_DELETED_CMD="curl -X POST \"$BASE_URL/scan/deleted\" \
  -H \"Content-Type: application/json\" \
  -d '{\"evidence_id\": $EVIDENCE_ID, \"partition_id\": $PARTITION_ID}'"

echo "Command:"
echo "$SCAN_DELETED_CMD"
echo ""
echo "Expected output: Count of deleted files found"
echo ""

read -p "Press Enter to continue to Step 5..."

# Step 5: List Deleted Files
echo ""
echo "========================================================================"
echo "Step 5: List Deleted Files"
echo "========================================================================"

LIST_DELETED_CMD="curl -X GET \"$BASE_URL/scan/deleted/$PARTITION_ID?limit=10\""

echo "Command:"
echo "$LIST_DELETED_CMD"
echo ""
echo "Expected output: First 10 deleted files with MACB timestamps"
echo ""

read -p "Press Enter to continue to Step 6..."

# Step 6: Recover Specific File
echo ""
echo "========================================================================"
echo "Step 6: Recover Deleted File (icat)"
echo "========================================================================"

DELETED_FILE_ID=1  # Replace with actual deleted file ID

RECOVER_CMD="curl -X POST \"$BASE_URL/recovery/recover/$DELETED_FILE_ID\""

echo "Command:"
echo "$RECOVER_CMD"
echo ""
echo "Expected output: Recovered file metadata with SHA-256 hash"
echo ""

read -p "Press Enter to continue to Step 7..."

# Step 7: File Carving
echo ""
echo "========================================================================"
echo "Step 7: Carve Files from Unallocated Space (Scalpel)"
echo "========================================================================"

CARVE_CMD="curl -X POST \"$BASE_URL/recovery/carve\" \
  -H \"Content-Type: application/json\" \
  -d '{\"evidence_id\": $EVIDENCE_ID, \"partition_id\": $PARTITION_ID}'"

echo "Command:"
echo "$CARVE_CMD"
echo ""
echo "Expected output: Count of carved files"
echo ""
echo "⚠️  WARNING: This can take a VERY long time for large disks!"
echo ""

read -p "Press Enter to continue to Step 8..."

# Step 8: Generate Timeline
echo ""
echo "========================================================================"
echo "Step 8: Generate MACB Timeline"
echo "========================================================================"

TIMELINE_CMD="curl -X GET \"$BASE_URL/forensics/timeline/$EVIDENCE_ID\""

echo "Command:"
echo "$TIMELINE_CMD"
echo ""
echo "Expected output: Chronological timeline of file events (MACB)"
echo ""

read -p "Press Enter to continue to Step 9..."

# Step 9: Download Recovered File
echo ""
echo "========================================================================"
echo "Step 9: Download Recovered File"
echo "========================================================================"

RECOVERED_FILE_ID=1  # Replace with actual recovered file ID

DOWNLOAD_CMD="curl -X GET \"$BASE_URL/files/download/recovered/$RECOVERED_FILE_ID\" \
  --output recovered_file.bin"

echo "Command:"
echo "$DOWNLOAD_CMD"
echo ""
echo "Expected output: File download (saved as recovered_file.bin)"
echo ""

read -p "Press Enter to continue to Step 10..."

# Step 10: Generate Report
echo ""
echo "========================================================================"
echo "Step 10: Generate Forensic Report"
echo "========================================================================"

REPORT_CMD="curl -X POST \"$BASE_URL/forensics/report/generate\" \
  -H \"Content-Type: application/json\" \
  -d '{\"evidence_id\": $EVIDENCE_ID, \"format\": \"json\"}'"

echo "Command:"
echo "$REPORT_CMD"
echo ""
echo "Expected output: Complete forensic report (JSON)"
echo ""

read -p "Press Enter to continue to Step 11..."

# Step 11: View Audit Log
echo ""
echo "========================================================================"
echo "Step 11: View Audit Log (Chain of Custody)"
echo "========================================================================"

AUDIT_CMD="curl -X GET \"$BASE_URL/forensics/audit/log?evidence_id=$EVIDENCE_ID&limit=20\""

echo "Command:"
echo "$AUDIT_CMD"
echo ""
echo "Expected output: Complete audit trail of all operations"
echo ""

echo ""
echo "========================================================================"
echo "✅ Workflow Example Complete!"
echo "========================================================================"
echo ""
echo "This workflow demonstrates:"
echo "  ✓ Evidence upload and verification"
echo "  ✓ Partition detection (mmls)"
echo "  ✓ Deleted file enumeration (fls)"
echo "  ✓ File recovery (icat)"
echo "  ✓ File carving (Scalpel)"
echo "  ✓ Timeline generation (MACB)"
echo "  ✓ File download"
echo "  ✓ Report generation"
echo "  ✓ Audit logging"
echo ""
echo "For API documentation: http://localhost:8000/docs"
echo ""
