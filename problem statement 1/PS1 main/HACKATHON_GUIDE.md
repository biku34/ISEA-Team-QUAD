# 🚀 Timestomping Detection Tool - Hackathon Guide

## 📋 Quick Setup (5 minutes)

### 1. Install Dependencies
```bash
# Run the setup script
quick_setup.bat

# Or install manually
pip install python-dateutil colorama tabulate matplotlib seaborn pandas
```

### 2. Run the Demo
```bash
# GUI Application (Recommended for interactive demo)
python gui_detector.py

# Or automated demo
python demo.py
```

## 🎯 Demo Flow (Perfect for 5-minute presentation)

### **Step 1: The Attack** (1 minute)
- Creates `C:\Evidence\malware.exe`
- Uses PowerShell to timestomp it to 5 years ago
- File appears "old and safe" in Windows Explorer

### **Step 2: The Detection** (2 minutes)
- Runs our Python forensic tool
- Shows MFT timestamp analysis
- Detects $SI vs $FN discrepancies
- Queries USN Journal for actual creation time

### **Step 3: The Visualization** (2 minutes)
- Launches interactive timeline GUI
- Shows "The Lie" (forged 2021 timestamp)
- Shows "The Truth" (actual 2026 USN journal entry)
- **Big red "HIGH RISK DETECTED" banner**

## 🔧 Key Features Demonstrated

### **Triple Source Verification**
1. **$SI Timestamps** (easily forged) - extracted from MFT
2. **$FN Timestamps** (harder to forge) - extracted from MFT  
3. **USN Journal** (actual transaction time) - parsed from $USN Journal

### **Risk Assessment Algorithm**
- Flags files where $SI time is significantly earlier than USN Journal time
- Calculates risk scores based on timestamp discrepancies
- Provides clear forensic indicators

### **Interactive Timeline Visualization**
- Color-coded timeline showing forged vs actual timestamps
- Risk-based file categorization
- Detailed analysis display with forensic evidence

## � **NEW: Live Real-Time Monitoring**

### **Real-Time Timestomping Detection**
- **Live file system monitoring** using watchdog events
- **Instant alerts** when suspicious timestamp changes occur
- **GUI and CLI interfaces** for real-time monitoring
- **Automatic alert export** for forensic documentation

### **Live Monitor Features**
- **Multi-path monitoring**: Watch multiple directories simultaneously
- **File type filtering**: Focus on executables, DLLs, system files
- **Risk scoring**: Real-time threat assessment with configurable thresholds
- **Alert management**: View, filter, and export suspicious activity
- **Low overhead**: Efficient monitoring with minimal system impact

### **Usage Examples**
```bash
# CLI - Monitor system directories
python live_monitor.py

# GUI - Interactive monitoring interface
python live_monitor.py --gui

# Test live detection
python test_live_monitor.py
```

## �️ Tool Components

| Component | Purpose | Status |
|-----------|---------|--------|
| `live_monitor.py` | **NEW: Real-time monitoring** | ✅ Working |
| `gui_detector.py` | **NEW: GUI with file upload** | ✅ Working |
| `timestomp_detector.py` | Main detection engine | ✅ Working |
| `mft_analyzer.py` | MFT timestamp extraction | ✅ Live NTFS analysis |
| `usn_parser.py` | USN Journal parsing | ✅ Live Windows API |
| `timeline_viz.py` | Interactive visualization | ✅ Working |
| `demo.py` | Complete hackathon demo | ✅ Working |
| `test_live_monitor.py` | Live monitoring test | ✅ Working |

## 🔍 Live Disk Analysis Features

### **Direct NTFS Filesystem Access**
- **MFT analysis**: Reads directly from live NTFS filesystem
- **USN Journal**: Queries live Windows API for transaction records
- **No disk imaging required**: Works on running systems
- **Real-time detection**: Analyzes files as they exist now

### **Triple Source Verification**
1. **$SI Timestamps** (easily forged) - extracted from live MFT
2. **$FN Timestamps** (harder to forge) - extracted from live MFT  
3. **USN Journal** (actual transaction time) - parsed from live $USN Journal

## 🖥️ **NEW GUI Features**

### **File Upload Interface**
- **Drag & drop** or browse to select files
- **Real-time analysis** with progress tracking
- **Multi-tab results** display (Summary, Details, Report)

### **Risk Assessment Dashboard**
- **Color-coded risk indicators** (Green/Yellow/Red)
- **Quantified risk scores** (0-100)
- **Forensic indicators** with explanations

### **Automatic Report Generation**
- **JSON reports** saved to `reports/` folder
- **Timestamped filenames** for organization
- **Export functionality** for documentation

### **Interactive Results**
- **Summary tab**: Quick overview with risk level
- **Details tab**: Technical forensic analysis
- **Report tab**: Full JSON report with save option

## 🎪 Demo Script Talking Points

### **Introduction (30 seconds)**
> "Attackers use timestomping to hide malicious files by faking their creation dates. Today I'll show how our forensic tool detects this anti-forensics technique using NTFS MFT analysis and USN Journal forensics."

### **The Attack (1 minute)**
> "Watch as I create this 'malware.exe' file and use PowerShell to change its creation date to 5 years ago. In Windows Explorer, it now looks like an old, harmless file from 2021."

### **The Detection (2 minutes)**
> "Our tool analyzes three sources: the easily forged $Standard_Information attribute, the harder-to-forge $File_Name attribute, and the USN Journal which records the actual file creation transaction. Look! It detected a 5-year discrepancy between the forged timestamp and the actual USN journal entry."

### **The Reveal (1.5 minutes)**
> "The timeline visualization shows the lie versus the truth. The red line shows the file appearing in 2021, but the blue USN journal entry proves it was actually created today. This is a clear case of timestomping - HIGH RISK DETECTED!"

## 🏆 Why This Wins

### **Technical Excellence**
- **Real forensic methodology** used by actual investigators
- **Triple-source verification** makes detection extremely reliable
- **USN Journal integration** provides ground truth timestamps

### **Visual Impact**
- **Interactive timeline** clearly shows the deception
- **Risk scoring** provides quantifiable evidence
- **Color-coded visualization** makes findings obvious

### **Practical Value**
- **Works on live systems** without disk images
- **JSON reports** for forensic documentation
- **Scalable** to scan entire directories

## 🔍 Technical Details

### **MFT Analysis**
- Extracts $Standard_Information ($SI) timestamps
- Extracts $File_Name ($FN) timestamps
- Compares discrepancies between SI and FN attributes

### **USN Journal Parsing**
- Reads $USN Journal entries using Windows API
- Finds actual file creation events
- Provides ground truth timestamps

### **Risk Assessment Logic**
```python
if SI_creation_time < USN_creation_time - 1_hour:
    risk_score += 50  # Major discrepancy
    indicators.append("SI creation time earlier than USN journal")
```

## 🚀 Future Enhancements

- **Full pytsk3 integration** for complete MFT parsing
- **$LogFile analysis** for additional transaction evidence
- **Batch processing** for enterprise forensics
- **Export to forensic formats** (CSV, XML)

## 📞 System Requirements

### **Required Components**
- **Windows OS** with NTFS filesystem
- **Administrator privileges** for USN Journal access
- **Python 3.7+** with dependencies from requirements.txt
- **Live disk access** - works without disk imaging

### **Dependencies**
```bash
pip install python-dateutil colorama tabulate matplotlib seaborn pandas
```

---

**Good luck with the hackathon!** 🎉
