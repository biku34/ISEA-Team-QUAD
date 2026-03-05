# Timestomping Detection Tool

A Python-based forensic tool that detects timestomping on NTFS file systems by analyzing MFT timestamps and USN Journal entries.

## Features

- **MFT Analysis**: Extracts and compares $Standard_Information ($SI) vs $File_Name ($FN) attributes
- **USN Journal Parsing**: Analyzes $USN Journal to find actual write times
- **Risk Assessment**: Flags files with timestamp discrepancies as "High Risk"
- **Timeline Visualization**: Visual comparison of forged vs actual timestamps
- **JSON Reporting**: Detailed forensic reports in JSON format
- **Automatic Fallback**: Uses real USN parser when available, falls back to simulation when not
- **GUI Interface**: File upload with real-time analysis and interactive results

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### GUI Application (Recommended)
```bash
python gui_detector.py
```

### Command Line Interface
```bash
python timestomp_detector.py --target "C:\Evidence" --output "report.json"
```

### Demo Mode
```bash
python demo.py
```

## USN Parser Behavior

The tool automatically selects the appropriate USN parser based on system capabilities:

### Real USN Parser (Preferred)
- **When available**: Uses Windows API to access actual USN Journal
- **Requirements**: Windows API access, appropriate permissions
- **Advantage**: Provides true forensic timestamps from NTFS journal
- **Fallback**: Automatically switches to fallback if access fails

### Fallback USN Parser (Demo/Compatibility)
- **When used**: Real parser unavailable or access denied
- **Behavior**: Simulates USN events for demonstration purposes
- **Advantage**: Ensures tool works in any environment
- **Detection**: Still effective for demonstrating timestomping concepts

### Selection Logic
1. Try to import and initialize real USN parser
2. Test access to USN Journal
3. If successful, use real parser for accurate timestamps
4. If failed, automatically fall back to simulation mode
5. Continue with full analysis regardless of parser type

## Administrator Access

The USN Journal parser requires administrator privileges for full functionality:

### Automatic Handling
- **Detects permission errors** automatically
- **Falls back to simulation** when access denied
- **Shows user-friendly warnings** with options
- **Provides admin elevation** for full functionality

### Manual Elevation
```bash
# Run with administrator privileges
python run_as_admin.py

# Or run GUI normally (will prompt if needed)
python gui_detector.py
```

### Expected Behavior
- **Standard User**: Uses fallback USN parser (simulated events)
- **Administrator**: Uses real USN parser (actual journal data)
- **Permission Denied**: Automatic fallback with user notification

1. **Attack**: Create file with forged timestamps
2. **Detection**: Run tool to expose discrepancies
3. **Visualization**: Timeline comparison showing tampering

## Architecture

- `gui_detector.py`: GUI application with file upload
- `timestomp_detector.py`: Main detection engine
- `mft_analyzer.py`: MFT timestamp extraction
- `usn_parser.py`: USN Journal analysis
- `timeline_viz.py`: Visualization component
- `demo.py`: Hackathon demonstration script
