#!/usr/bin/env python3
"""
GUI Timestomping Detection Tool - Live Disk Analysis Version
- MFT analysis: Reads directly from live NTFS filesystem
- USN Journal: Queries live Windows API for transaction records
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import json
import datetime
from pathlib import Path
import tempfile
import shutil
from typing import Dict, List

# Import live disk analysis components
from mft_analyzer import MFTAnalyzer
from usn_parser import USNJournalParser

class TimestompDetector:
    """Simplified detector for GUI"""
    
    def __init__(self, target_path: str, volume_path: str = None):
        """
        Initialize detector
        
        Args:
            target_path: Path to scan (directory or file)
            volume_path: Volume path for USN journal (e.g., "C:")
        """
        self.target_path = target_path
        self.volume_path = volume_path or self._get_volume_path()
        
        self.mft_analyzer = MFTAnalyzer()
        self.usn_parser = USNJournalParser(self.volume_path)
        
    def _get_volume_path(self):
        """Get volume path for USN parser"""
        # For demo, use current working directory's drive
        import os
        current_dir = os.getcwd()
        if len(current_dir) >= 2 and current_dir[1] == ':':
            return current_dir[0].upper()
        return 'C'
        
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a single file"""
        file_result = {
            'file_path': file_path,
            'filename': os.path.basename(file_path),
            'mft_analysis': {},
            'usn_analysis': {},
            'risk_assessment': {
                'risk_level': 'low',
                'risk_score': 0,
                'indicators': []
            }
        }
        
        # MFT Analysis
        mft_data = self.mft_analyzer.extract_timestamps(file_path)
        file_result['mft_analysis'] = mft_data
        
        # USN Journal Analysis
        filename = os.path.basename(file_path)
        print(f"[DETECTOR] Analyzing USN Journal for: {filename}")
        usn_events = self.usn_parser.find_file_creation_events(filename, max_hours=24)
        print(f"[DETECTOR] USN events found: {len(usn_events)}")
        for event in usn_events:
            print(f"[DETECTOR] USN Event: {event.get('timestamp')} - {event.get('reasons')}")
                
        file_result['usn_analysis'] = {
            'creation_events': usn_events,
            'event_count': len(usn_events)
        }
        
        # Risk Assessment
        file_result['risk_assessment'] = self._assess_risk(mft_data, usn_events, file_result)
        
        return file_result
        
    def _assess_risk(self, mft_data, usn_events, file_result):
        """Assess risk level"""
        risk_score = 0
        indicators = []
        
        # Check MFT discrepancies
        discrepancies = mft_data.get('discrepancies', [])
        if discrepancies:
            risk_score += len(discrepancies) * 10
            indicators.append(f"MFT timestamp discrepancies: {len(discrepancies)}")
            
        # Check USN vs MFT timestamps
        if usn_events:
            latest_event = usn_events[-1]
            usn_timestamp = latest_event.get('timestamp')
            
            if usn_timestamp:
                si_timestamps = mft_data.get('si_timestamps', {})
                si_creation = si_timestamps.get('creation')
                
                if si_creation:
                    try:
                        si_time = datetime.datetime.fromisoformat(si_creation)
                        usn_time = datetime.datetime.fromisoformat(usn_timestamp)
                        time_diff = (usn_time - si_time).total_seconds()
                        
                        if time_diff > 3600:  # More than 1 hour
                            risk_score += 50
                            indicators.append(f"SI creation time {time_diff/3600:.1f} hours earlier than USN journal")
                            
                            if time_diff > 86400:  # More than 24 hours
                                risk_score += 50
                                indicators.append("Major timestamp discrepancy detected (>24 hours)")
                                
                        # Also check if SI time is in future compared to USN
                        elif time_diff < -3600:  # SI is more than 1 hour in future
                            risk_score += 30
                            indicators.append(f"SI creation time {abs(time_diff)/3600:.1f} hours later than USN journal")
                                
                    except Exception:
                        pass
                        
        # Additional risk factors
        filename = file_result.get('filename', '').lower()
        if any(suspicious in filename for suspicious in ['malware', 'virus', 'trojan', 'backdoor', 'rootkit']):
            risk_score += 20
            indicators.append("Suspicious filename detected")
            
        if filename.endswith(('.exe', '.scr', '.bat', '.cmd', '.ps1')):
            risk_score += 10
            indicators.append("Executable file type")
            
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
            
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'indicators': indicators
        }

class TimestompDetectorGUI:
    """GUI for timestomping detection with file upload"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Timestomping Detection Tool - File Upload")
        self.root.geometry("900x700")
        
        # Force window to front and make it visible
        self.root.lift()
        self.root.attributes('-topmost', True)
        self.root.after(1000, lambda: self.root.attributes('-topmost', False))
        
        # Center the window
        self.root.update_idletasks()
        width = 900
        height = 700
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Initialize variables
        self.current_file = None
        self.analysis_running = False
        
        # Create main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="🔍 TIMESTOMPING DETECTION TOOL",
            font=('Arial', 16, 'bold')
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # File Upload Section
        upload_frame = ttk.LabelFrame(main_frame, text="📁 File Upload", padding="10")
        upload_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        upload_frame.columnconfigure(1, weight=1)
        
        ttk.Label(upload_frame, text="Select file to analyze:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(upload_frame, textvariable=self.file_path_var, state='readonly')
        self.file_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        self.browse_button = ttk.Button(upload_frame, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=1, column=1, sticky=tk.W, padx=(5, 0))
        
        self.upload_button = ttk.Button(
            upload_frame, 
            text="🚀 Upload & Analyze", 
            command=self.upload_and_analyze,
            style='Accent.TButton'
        )
        self.upload_button.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        
        # Progress Section
        progress_frame = ttk.LabelFrame(main_frame, text="📊 Analysis Progress", padding="10")
        progress_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.StringVar(value="Ready to analyze files...")
        self.progress_label = ttk.Label(progress_frame, textvariable=self.progress_var)
        self.progress_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # Results Section
        results_frame = ttk.LabelFrame(main_frame, text="📋 Analysis Results", padding="10")
        results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Create notebook for multiple views
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.summary_frame, text="📊 Summary")
        self.setup_summary_tab()
        
        # Details tab
        self.details_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.details_frame, text="🔍 Details")
        self.setup_details_tab()
        
        # Report tab
        self.report_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.report_frame, text="📄 Report")
        self.setup_report_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Initialize detector components
        self.mft_analyzer = MFTAnalyzer()
        self.usn_parser = USNJournalParser(self._get_volume_path())
        print(f"[GUI] Live USN parser initialized: {type(self.usn_parser)}")
        
    def _get_volume_path(self):
        """Get volume path for USN parser"""
        # For demo, use current working directory's drive
        import os
        current_dir = os.getcwd()
        if len(current_dir) >= 2 and current_dir[1] == ':':
            return current_dir[0].upper()
        return 'C'
            
    def browse_file(self):
        """Browse for file to analyze"""
        file_path = filedialog.askopenfilename(
            title="Select file to analyze",
            filetypes=[
                ("All files", "*.*"),
                ("Executable files", "*.exe *.scr *.bat *.cmd *.ps1"),
                ("Document files", "*.doc *.docx *.pdf *.txt")
            ]
        )
        
        if file_path:
            self.file_path_var.set(file_path)
            self.current_file = file_path
            
    def upload_and_analyze(self):
        """Upload file and perform analysis"""
        if self.analysis_running:
            messagebox.showwarning("Warning", "Analysis already in progress")
            return
            
        if not self.current_file:
            messagebox.showerror("Error", "Please select a file to analyze")
            return
            
        self.analysis_running = True
        self.upload_button.config(state='disabled')
        self.browse_button.config(state='disabled')
        
        self.update_progress("Starting analysis...", True)
        
        # Perform analysis in separate thread
        def analyze_thread():
            try:
                # MFT Analysis
                mft_data = self.mft_analyzer.extract_timestamps(self.current_file)
                
                # USN Journal Analysis
                filename = os.path.basename(self.current_file)
                print(f"[GUI] Analyzing USN Journal for: {filename}")
                usn_events = self.usn_parser.find_file_creation_events(filename, max_hours=24)
                print(f"[GUI] USN events found: {len(usn_events)}")
                for event in usn_events:
                    print(f"[GUI] USN Event: {event.get('timestamp')} - {event.get('reasons')}")
                
                # Risk Assessment
                file_result = {
                    'file_path': self.current_file,
                    'filename': filename,
                    'mft_analysis': mft_data,
                    'usn_analysis': {
                        'creation_events': usn_events,
                        'event_count': len(usn_events)
                    },
                    'risk_assessment': self._assess_risk(mft_data, usn_events, filename)
                }
                
                # Update GUI with results
                self.root.after(0, lambda: self.display_results(file_result))
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"Analysis failed: {str(e)}"))
            finally:
                self.analysis_running = False
                self.root.after(0, self.enable_controls)
                
        # Start analysis thread
        thread = threading.Thread(target=analyze_thread)
        thread.daemon = True
        thread.start()
        
    def display_results(self, file_result):
        """Display analysis results"""
        self.update_summary(file_result)
        self.update_details(file_result)
        self.update_report(file_result)
        self.update_progress("Analysis completed", False)
        
    def update_summary(self, file_result):
        """Update summary tab"""
        # Clear previous content
        for widget in self.summary_frame.winfo_children():
            widget.destroy()
            
        # Risk indicator
        risk_assessment = file_result.get('risk_assessment', {})
        risk_level = risk_assessment.get('risk_level', 'unknown')
        risk_score = risk_assessment.get('risk_score', 0)
        
        # Color coding
        colors = {
            'low': ('#27ae60', 'LOW RISK'),
            'medium': ('#f39c12', 'MEDIUM RISK'),
            'high': ('#e74c3c', 'HIGH RISK DETECTED'),
            'unknown': ('#7f8c8d', 'UNKNOWN')
        }
        
        color, text = colors.get(risk_level, colors['unknown'])
        
        risk_label = tk.Label(
            self.summary_frame,
            text=text,
            font=('Arial', 14, 'bold'),
            bg=color,
            fg='white'
        )
        risk_label.pack(pady=20)
        
        # Summary info frame
        info_frame = ttk.Frame(self.summary_frame)
        info_frame.pack(pady=10)
        
        # Summary labels
        summary_items = [
            ('File Name:', os.path.basename(file_result.get('file_path', ''))),
            ('File Size:', self.format_file_size(os.path.getsize(file_result.get('file_path', 0)))),
            ('Risk Level:', risk_level.upper()),
            ('Risk Score:', str(risk_score)),
            ('MFT Discrepancies:', str(len(file_result.get('mft_analysis', {}).get('discrepancies', [])))),
            ('USN Events:', str(file_result.get('usn_analysis', {}).get('event_count', 0)))
        ]
        
        for i, (label, value) in enumerate(summary_items):
            ttk.Label(info_frame, text=label, font=('Arial', 10, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=10, pady=2)
            ttk.Label(info_frame, text=value).grid(row=i, column=1, sticky=tk.W, padx=10, pady=2)
            
    def update_details(self, file_result):
        """Update details tab"""
        # Clear previous content
        self.details_text.delete(1.0, tk.END)
        
        # Format details
        details = []
        details.append("=" * 60)
        details.append("TIMESTOMPING ANALYSIS DETAILS")
        details.append("=" * 60)
        details.append(f"File: {file_result.get('file_path', 'Unknown')}")
        details.append(f"Analysis Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        details.append("")
        
        # Risk assessment
        risk_assessment = file_result.get('risk_assessment', {})
        details.append("RISK ASSESSMENT:")
        details.append(f"  Level: {risk_assessment.get('risk_level', 'Unknown')}")
        details.append(f"  Score: {risk_assessment.get('risk_score', 0)}")
        details.append("")
        
        # Indicators
        indicators = risk_assessment.get('indicators', [])
        if indicators:
            details.append("INDICATORS:")
            for indicator in indicators:
                details.append(f"  - {indicator}")
            details.append("")
            
        # MFT analysis
        mft_analysis = file_result.get('mft_analysis', {})
        details.append("MFT TIMESTAMP ANALYSIS:")
        
        si_timestamps = mft_analysis.get('si_timestamps', {})
        if si_timestamps:
            details.append("  $SI Timestamps:")
            for ts_type, timestamp in si_timestamps.items():
                details.append(f"    {ts_type}: {timestamp}")
                
        fn_timestamps = mft_analysis.get('fn_timestamps', {})
        if fn_timestamps:
            details.append("  $FN Timestamps:")
            for ts_type, timestamp in fn_timestamps.items():
                details.append(f"    {ts_type}: {timestamp}")
                
        discrepancies = mft_analysis.get('discrepancies', [])
        if discrepancies:
            details.append("  Discrepancies:")
            for disc in discrepancies:
                details.append(f"    - {disc.get('type', 'Unknown')}: {disc.get('difference_seconds', 0):.1f}s ({disc.get('severity', 'Unknown')})")
            details.append("")
            
        # USN analysis
        usn_analysis = file_result.get('usn_analysis', {})
        details.append("USN JOURNAL ANALYSIS:")
        details.append(f"  Events Found: {usn_analysis.get('event_count', 0)}")
        
        creation_events = usn_analysis.get('creation_events', [])
        if creation_events:
            details.append("  Creation Events:")
            for event in creation_events[:3]:  # Show first 3
                timestamp = event.get('timestamp', 'Unknown')
                reasons = event.get('reasons', [])
                details.append(f"    - {timestamp}: {', '.join(reasons)}")
                
        self.details_text.insert(1.0, tk.END, '\n'.join(details))
        
    def update_report(self, file_result):
        """Update report tab"""
        # Clear previous content
        self.report_text.delete(1.0, tk.END)
        
        # Create JSON report
        report = {
            'scan_info': {
                'target_path': file_result.get('file_path', ''),
                'scan_time': datetime.datetime.now().isoformat(),
                'tool_version': '1.0.0'
            },
            'file_analysis': file_result
        }
        
        report_json = json.dumps(report, indent=2, default=str)
        self.report_text.insert(1.0, tk.END, report_json)
        
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
            
    def show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
        self.status_var.set("Error occurred")
        
    def enable_controls(self):
        """Re-enable upload controls"""
        self.upload_button.config(state='normal')
        self.browse_button.config(state='normal')
        
    def update_progress(self, message, start_progress=False):
        """Update progress message and bar"""
        self.progress_var.set(message)
        if start_progress:
            self.progress_bar.start(10)
        else:
            self.progress_bar.stop()
            
    def _assess_risk(self, mft_data, usn_events, filename):
        """Assess risk level"""
        risk_score = 0
        indicators = []
        
        # Check MFT discrepancies
        discrepancies = mft_data.get('discrepancies', [])
        if discrepancies:
            risk_score += len(discrepancies) * 10
            indicators.append(f"MFT timestamp discrepancies: {len(discrepancies)}")
            
        # Check USN vs MFT timestamps
        if usn_events:
            latest_event = usn_events[-1]
            usn_timestamp = latest_event.get('timestamp')
            
            if usn_timestamp:
                si_timestamps = mft_data.get('si_timestamps', {})
                si_creation = si_timestamps.get('creation')
                
                if si_creation:
                    try:
                        si_time = datetime.datetime.fromisoformat(si_creation)
                        usn_time = datetime.datetime.fromisoformat(usn_timestamp)
                        time_diff = (usn_time - si_time).total_seconds()
                        
                        if time_diff > 3600:  # More than 1 hour
                            risk_score += 50
                            indicators.append(f"SI creation time {time_diff/3600:.1f} hours earlier than USN journal")
                            
                            if time_diff > 86400:  # More than 24 hours
                                risk_score += 50
                                indicators.append("Major timestamp discrepancy detected (>24 hours)")
                                
                        # Also check if SI time is in future compared to USN
                        elif time_diff < -3600:  # SI is more than 1 hour in future
                            risk_score += 30
                            indicators.append(f"SI creation time {abs(time_diff)/3600:.1f} hours later than USN journal")
                                
                    except Exception:
                        pass
                        
        # Additional risk factors
        if any(suspicious in filename.lower() for suspicious in ['malware', 'virus', 'trojan', 'backdoor', 'rootkit']):
            risk_score += 20
            indicators.append("Suspicious filename detected")
            
        if filename.lower().endswith(('.exe', '.scr', '.bat', '.cmd', '.ps1')):
            risk_score += 10
            indicators.append("Executable file type")
            
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
            
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'indicators': indicators
        }
        
    def setup_summary_tab(self):
        """Setup summary tab"""
        # Risk indicator
        self.risk_label = tk.Label(
            self.summary_frame, 
            text="NO FILE ANALYZED",
            font=('Arial', 14, 'bold'),
            bg='#f0f0f0',
            fg='#7f8c8d'
        )
        self.risk_label.pack(pady=20)
        
        # Summary info frame
        info_frame = ttk.Frame(self.summary_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Summary labels
        self.summary_labels = {}
        summary_items = [
            ('File Name:', 'filename'),
            ('File Size:', 'filesize'),
            ('Risk Level:', 'risk_level'),
            ('Risk Score:', 'risk_score'),
            ('MFT Discrepancies:', 'mft_discrepancies'),
            ('USN Events:', 'usn_events'),
            ('Analysis Time:', 'analysis_time')
        ]
        
        for i, (label_text, key) in enumerate(summary_items):
            ttk.Label(info_frame, text=label_text, font=('Arial', 10, 'bold')).grid(row=i, column=0, sticky=tk.W, pady=2)
            self.summary_labels[key] = ttk.Label(info_frame, text="-")
            self.summary_labels[key].grid(row=i, column=1, sticky=tk.W, pady=2, padx=(10, 0))
            
    def setup_details_tab(self):
        """Setup details tab"""
        # Create scrolled text widget
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=30,
            font=('Courier', 9)
        )
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def setup_report_tab(self):
        """Setup report tab"""
        # Report controls
        controls_frame = ttk.Frame(self.report_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(controls_frame, text="📄 Save Report", command=self.save_report).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(controls_frame, text="📂 Open Reports Folder", command=self.open_reports_folder).pack(side=tk.LEFT)
        
        # Report text
        self.report_text = scrolledtext.ScrolledText(
            self.report_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=25,
            font=('Courier', 9)
        )
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
    def save_report(self):
        """Save current report"""
        report_content = self.report_text.get(1.0, tk.END)
        
        file_path = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(report_content)
                messagebox.showinfo("Success", f"Report saved to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")
                
    def open_reports_folder(self):
        """Open reports folder"""
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        try:
            os.startfile(reports_dir)
        except:
            messagebox.showinfo("Info", f"Reports folder: {reports_dir}")

def main():
    """Main function"""
    root = tk.Tk()
    app = TimestompDetectorGUI(root)
    root.mainloop()
