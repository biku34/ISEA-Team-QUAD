#!/usr/bin/env python3
"""
System-wide Timestomping Scanner
Scans entire system for timestamp anomalies and shows correlations
- MFT analysis: Reads directly from live NTFS filesystem
- USN Journal: Queries live Windows API for transaction records
"""

import os
import sys
import json
import datetime
import threading
from pathlib import Path
from typing import Dict, List, Tuple
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import live disk analysis components
from mft_analyzer import MFTAnalyzer
from usn_parser import USNJournalParser

class SystemTimestompScanner:
    """System-wide timestomping scanner with GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 System-wide Timestomping Scanner")
        self.root.geometry("1200x800")
        
        # Force window visibility
        self.root.lift()
        self.root.attributes('-topmost', True)
        self.root.after(2000, lambda: self.root.attributes('-topmost', False))
        
        # Center window
        self.root.update_idletasks()
        width = 1200
        height = 800
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Initialize components
        self.mft_analyzer = MFTAnalyzer()
        self.usn_parser = USNJournalParser(self._get_volume_path())
        self.scanning = False
        self.results = []
        
        # Create GUI
        self.create_widgets()
        
    def _get_volume_path(self):
        """Get system volume path"""
        current_dir = os.getcwd()
        if len(current_dir) >= 2 and current_dir[1] == ':':
            return current_dir[0].upper()
        return 'C'
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = ttk.Label(main_frame, text="🔍 SYSTEM-WIDE TIMESTOMPING SCANNER", 
                         font=('Arial', 18, 'bold'))
        title.pack(pady=(0, 20))
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="🎛️ Scan Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Scan options
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(options_frame, text="Scan Directory:").pack(side=tk.LEFT, padx=(0, 10))
        self.scan_path_var = tk.StringVar(value="C:\\")
        self.path_entry = ttk.Entry(options_frame, textvariable=self.scan_path_var, width=50)
        self.path_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(options_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT, padx=(0, 10))
        
        # File filters
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_executables = tk.BooleanVar(value=True)
        self.scan_documents = tk.BooleanVar(value=True)
        self.scan_all_files = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(filter_frame, text="Executable Files (.exe, .dll, .sys)", 
                       variable=self.scan_executables).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Checkbutton(filter_frame, text="Documents (.doc, .pdf, .txt)", 
                       variable=self.scan_documents).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Checkbutton(filter_frame, text="All Files (Slower)", 
                       variable=self.scan_all_files).pack(side=tk.LEFT)
        
        # Scan buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.scan_button = ttk.Button(button_frame, text="🚀 START SYSTEM SCAN", 
                                     command=self.start_system_scan, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="⏹️ STOP", 
                                      command=self.stop_scan, state='disabled')
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="📄 Export Results", 
                  command=self.export_results).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="🗑️ Clear Results", 
                  command=self.clear_results).pack(side=tk.LEFT)
        
        # Progress
        progress_frame = ttk.LabelFrame(main_frame, text="📊 Scan Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.StringVar(value="Ready to scan system...")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Results area with tabs
        results_frame = ttk.LabelFrame(main_frame, text="📋 Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.summary_frame, text="📊 Summary")
        self.setup_summary_tab()
        
        # Detailed results tab
        self.details_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.details_frame, text="🔍 Detailed Results")
        self.setup_details_tab()
        
        # Timeline tab
        self.timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.timeline_frame, text="📅 Timeline View")
        self.setup_timeline_tab()
        
        # Statistics tab
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="📈 Statistics")
        self.setup_stats_tab()
        
    def setup_summary_tab(self):
        """Setup summary tab"""
        # Summary text
        self.summary_text = scrolledtext.ScrolledText(
            self.summary_frame, height=20, wrap=tk.WORD, font=('Courier', 10)
        )
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_details_tab(self):
        """Setup detailed results tab"""
        # Create treeview for detailed results
        columns = ('File', 'Risk', 'SI_Time', 'FN_Time', 'USN_Time', 'Discrepancy', 'Indicators')
        self.details_tree = ttk.Treeview(self.details_frame, columns=columns, show='tree headings')
        
        # Configure columns
        self.details_tree.heading('#0', text='Path')
        self.details_tree.column('#0', width=300)
        
        for col in columns:
            self.details_tree.heading(col, text=col.replace('_', ' '))
            if col == 'File':
                self.details_tree.column(col, width=100)
            elif col == 'Risk':
                self.details_tree.column(col, width=80)
            elif 'Time' in col:
                self.details_tree.column(col, width=150)
            elif col == 'Discrepancy':
                self.details_tree.column(col, width=100)
            else:
                self.details_tree.column(col, width=200)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(self.details_frame, orient='vertical', command=self.details_tree.yview)
        h_scrollbar = ttk.Scrollbar(self.details_frame, orient='horizontal', command=self.details_tree.xview)
        
        self.details_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        self.details_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        self.details_frame.grid_rowconfigure(0, weight=1)
        self.details_frame.grid_columnconfigure(0, weight=1)
        
    def setup_timeline_tab(self):
        """Setup timeline view tab"""
        self.timeline_text = scrolledtext.ScrolledText(
            self.timeline_frame, height=20, wrap=tk.WORD, font=('Courier', 10)
        )
        self.timeline_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_stats_tab(self):
        """Setup statistics tab"""
        self.stats_text = scrolledtext.ScrolledText(
            self.stats_frame, height=20, wrap=tk.WORD, font=('Courier', 10)
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def browse_directory(self):
        """Browse for scan directory"""
        directory = filedialog.askdirectory(
            title="Select Directory to Scan",
            initialdir=self.scan_path_var.get()
        )
        if directory:
            self.scan_path_var.set(directory)
            
    def start_system_scan(self):
        """Start system-wide scan"""
        if self.scanning:
            return
            
        scan_path = self.scan_path_var.get()
        if not os.path.exists(scan_path):
            messagebox.showerror("Error", f"Directory does not exist: {scan_path}")
            return
            
        self.scanning = True
        self.results = []
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        
        # Clear previous results
        self.clear_results()
        
        # Start scan in thread
        thread = threading.Thread(target=self.scan_system, args=(scan_path,))
        thread.daemon = True
        thread.start()
        
    def stop_scan(self):
        """Stop scanning"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_var.set("Scan stopped by user")
        
    def scan_system(self, scan_path):
        """Scan system for timestomping"""
        try:
            self.root.after(0, lambda: self.progress_var.set(f"Scanning {scan_path}..."))
            
            # Get file list
            files_to_scan = self.get_files_to_scan(scan_path)
            total_files = len(files_to_scan)
            
            if total_files == 0:
                self.root.after(0, lambda: self.progress_var.set("No files found to scan"))
                return
                
            self.root.after(0, lambda: self.progress_var.set(f"Found {total_files} files to scan..."))
            
            # Scan files with progress
            scanned_count = 0
            suspicious_files = []
            
            for i, file_path in enumerate(files_to_scan):
                if not self.scanning:
                    break
                    
                try:
                    # Update progress
                    progress = (i / total_files) * 100
                    self.root.after(0, lambda p=progress: self.progress_bar.config(value=p))
                    self.root.after(0, lambda c=i, t=total_files: 
                                   self.progress_var.set(f"Scanning file {c+1}/{t}: {os.path.basename(files_to_scan[min(c, t-1)])}"))
                    
                    # Analyze file
                    result = self.analyze_file(file_path)
                    if result:
                        self.results.append(result)
                        if result['risk_assessment']['risk_level'] in ['medium', 'high']:
                            suspicious_files.append(result)
                            
                    scanned_count += 1
                    
                    # Update GUI periodically
                    if i % 10 == 0:
                        self.root.after(0, self.update_results_display)
                        
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")
                    continue
                    
            # Final update
            self.root.after(0, lambda: self.progress_bar.config(value=100))
            self.root.after(0, lambda: self.progress_var.set(f"Scan completed: {scanned_count} files scanned"))
            self.root.after(0, self.update_results_display)
            self.root.after(0, self.generate_statistics)
            
        except Exception as e:
            self.root.after(0, lambda: self.progress_var.set(f"Scan error: {str(e)}"))
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_button.config(state='normal'))
            self.root.after(0, lambda: self.stop_button.config(state='disabled'))
            
    def get_files_to_scan(self, scan_path):
        """Get list of files to scan based on filters"""
        files_to_scan = []
        
        try:
            for root, dirs, files in os.walk(scan_path):
                for file in files:
                    if not self.scanning:
                        break
                        
                    file_path = os.path.join(root, file)
                    
                    # Apply filters
                    if self.scan_all_files.get():
                        files_to_scan.append(file_path)
                    elif self.scan_executables.get() and file.lower().endswith(('.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1')):
                        files_to_scan.append(file_path)
                    elif self.scan_documents.get() and file.lower().endswith(('.doc', '.docx', '.pdf', '.txt', '.rtf')):
                        files_to_scan.append(file_path)
                        
                if not self.scanning:
                    break
                    
        except Exception as e:
            print(f"Error walking directory {scan_path}: {e}")
            
        return files_to_scan
        
    def analyze_file(self, file_path):
        """Analyze single file for timestomping"""
        try:
            # MFT Analysis
            mft_data = self.mft_analyzer.extract_timestamps(file_path)
            
            # USN Journal Analysis
            filename = os.path.basename(file_path)
            usn_events = self.usn_parser.find_file_creation_events(filename, max_hours=24)
            
            # Risk Assessment
            risk_assessment = self.assess_risk(mft_data, usn_events, filename)
            
            return {
                'file_path': file_path,
                'filename': filename,
                'mft_analysis': mft_data,
                'usn_analysis': {
                    'creation_events': usn_events,
                    'event_count': len(usn_events)
                },
                'risk_assessment': risk_assessment
            }
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            return None
            
    def assess_risk(self, mft_data, usn_events, filename):
        """Assess risk level for file"""
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
                        time_diff = abs((usn_time - si_time).total_seconds())
                        
                        if time_diff > 3600:  # More than 1 hour
                            risk_score += 50
                            indicators.append(f"Timestamp discrepancy: {time_diff/3600:.1f} hours")
                            
                    except Exception:
                        pass
                        
        # Additional risk factors
        if any(suspicious in filename.lower() for suspicious in ['malware', 'virus', 'trojan', 'backdoor', 'rootkit']):
            risk_score += 20
            indicators.append("Suspicious filename detected")
            
        if filename.lower().endswith(('.exe', '.dll', '.sys', '.scr')):
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
        
    def update_results_display(self):
        """Update results display"""
        if not self.results:
            return
            
        # Update summary
        self.update_summary()
        
        # Update detailed results
        self.update_details()
        
        # Update timeline
        self.update_timeline()
        
    def update_summary(self):
        """Update summary tab"""
        self.summary_text.delete(1.0, tk.END)
        
        total_files = len(self.results)
        high_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'high')
        medium_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'medium')
        low_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'low')
        
        summary = f"""
🔍 SYSTEM-WIDE TIMESTOMPING SCAN RESULTS
{'='*60}

📊 SCAN STATISTICS:
  Total Files Scanned: {total_files}
  High Risk Files: {high_risk}
  Medium Risk Files: {medium_risk}
  Low Risk Files: {low_risk}
  Suspicious Files: {high_risk + medium_risk}

🎯 RISK ASSESSMENT:
"""
        
        if high_risk > 0:
            summary += f"  🔴 HIGH RISK DETECTED: {high_risk} files with severe timestomping\n"
        if medium_risk > 0:
            summary += f"  🟡 MEDIUM RISK: {medium_risk} files with potential timestomping\n"
        if low_risk > 0:
            summary += f"  🟢 LOW RISK: {low_risk} files appear normal\n"
            
        summary += f"\n🔍 TOP SUSPICIOUS FILES:\n"
        
        # Show top 5 suspicious files
        suspicious_files = sorted(self.results, 
                                key=lambda x: x['risk_assessment']['risk_score'], 
                                reverse=True)[:5]
        
        for i, result in enumerate(suspicious_files, 1):
            risk = result['risk_assessment']
            filename = result['filename']
            score = risk['risk_score']
            level = risk['risk_level'].upper()
            
            summary += f"  {i}. {filename} - {level} (Score: {score})\n"
            
        self.summary_text.insert(tk.END, summary)
        
    def update_details(self):
        """Update detailed results tree"""
        # Clear existing items
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
            
        # Add results
        for result in self.results:
            file_path = result['file_path']
            filename = result['filename']
            risk = result['risk_assessment']
            mft = result['mft_analysis']
            usn = result['usn_analysis']
            
            # Get timestamps
            si_time = mft.get('si_timestamps', {}).get('creation', 'N/A')
            fn_time = mft.get('fn_timestamps', {}).get('creation', 'N/A')
            usn_time = usn.get('creation_events', [{}])[0].get('timestamp', 'N/A') if usn.get('creation_events') else 'N/A'
            
            # Calculate discrepancy
            discrepancy = 'N/A'
            if si_time != 'N/A' and fn_time != 'N/A' and si_time != fn_time:
                try:
                    si_dt = datetime.datetime.fromisoformat(si_time)
                    fn_dt = datetime.datetime.fromisoformat(fn_time)
                    diff = abs((fn_dt - si_dt).total_seconds())
                    discrepancy = f"{diff/3600:.1f}h" if diff > 3600 else f"{diff:.0f}s"
                except:
                    discrepancy = "Error"
                    
            # Format indicators
            indicators = ', '.join(risk['indicators'][:2])  # Show first 2 indicators
            if len(risk['indicators']) > 2:
                indicators += f" (+{len(risk['indicators'])-2} more)"
                
            # Color coding for risk level
            risk_level = risk['risk_level']
            risk_display = f"🔴{risk_level.upper()}" if risk_level == 'high' else f"🟡{risk_level.upper()}" if risk_level == 'medium' else f"🟢{risk_level.upper()}"
            
            # Insert into tree
            self.details_tree.insert('', 'end', text=file_path, values=(
                filename,
                risk_display,
                si_time[:19] if si_time != 'N/A' else 'N/A',
                fn_time[:19] if fn_time != 'N/A' else 'N/A',
                usn_time[:19] if usn_time != 'N/A' else 'N/A',
                discrepancy,
                indicators
            ))
            
    def update_timeline(self):
        """Update timeline view"""
        self.timeline_text.delete(1.0, tk.END)
        
        timeline = "📅 TIMESTOMPING TIMELINE ANALYSIS\n"
        timeline += "=" * 60 + "\n\n"
        
        # Sort results by risk score
        suspicious_files = sorted(self.results, 
                                key=lambda x: x['risk_assessment']['risk_score'], 
                                reverse=True)
        
        for result in suspicious_files[:20]:  # Show top 20
            if result['risk_assessment']['risk_score'] < 30:
                break  # Skip low risk files
                
            filename = result['filename']
            risk = result['risk_assessment']
            mft = result['mft_analysis']
            usn = result['usn_analysis']
            
            timeline += f"🔍 {filename}\n"
            timeline += f"   Risk Level: {risk['risk_level'].upper()} (Score: {risk['risk_score']})\n"
            
            # Show timestamps
            si_time = mft.get('si_timestamps', {}).get('creation')
            fn_time = mft.get('fn_timestamps', {}).get('creation')
            
            if si_time:
                timeline += f"   $SI Creation: {si_time}\n"
            if fn_time:
                timeline += f"   $FN Creation: {fn_time}\n"
                
            # Show USN events
            if usn.get('creation_events'):
                for event in usn['creation_events'][:3]:
                    timeline += f"   USN Event: {event.get('timestamp')} - {', '.join(event.get('reasons', []))}\n"
                    
            # Show indicators
            if risk['indicators']:
                timeline += f"   Indicators: {', '.join(risk['indicators'])}\n"
                
            timeline += "\n"
            
        self.timeline_text.insert(tk.END, timeline)
        
    def generate_statistics(self):
        """Generate comprehensive statistics"""
        self.stats_text.delete(1.0, tk.END)
        
        if not self.results:
            self.stats_text.insert(tk.END, "No scan results available.")
            return
            
        stats = "📈 COMPREHENSIVE SCAN STATISTICS\n"
        stats += "=" * 60 + "\n\n"
        
        total = len(self.results)
        high_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'high')
        medium_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'medium')
        low_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'low')
        
        stats += f"📊 OVERALL STATISTICS:\n"
        stats += f"  Total Files Analyzed: {total}\n"
        stats += f"  High Risk Files: {high_risk} ({high_risk/total*100:.1f}%)\n"
        stats += f"  Medium Risk Files: {medium_risk} ({medium_risk/total*100:.1f}%)\n"
        stats += f"  Low Risk Files: {low_risk} ({low_risk/total*100:.1f}%)\n"
        stats += f"  Suspicious Rate: {(high_risk + medium_risk)/total*100:.1f}%\n\n"
        
        # File type statistics
        exe_files = sum(1 for r in self.results if r['filename'].lower().endswith('.exe'))
        dll_files = sum(1 for r in self.results if r['filename'].lower().endswith('.dll'))
        doc_files = sum(1 for r in self.results if r['filename'].lower().endswith(('.doc', '.docx', '.pdf')))
        
        stats += f"📁 FILE TYPE ANALYSIS:\n"
        stats += f"  Executable Files (.exe): {exe_files}\n"
        stats += f"  Library Files (.dll): {dll_files}\n"
        stats += f"  Document Files: {doc_files}\n\n"
        
        # Risk indicators
        all_indicators = []
        for result in self.results:
            all_indicators.extend(result['risk_assessment']['indicators'])
            
        indicator_counts = {}
        for indicator in all_indicators:
            indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
            
        stats += f"⚠️  RISK INDICATORS FREQUENCY:\n"
        for indicator, count in sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True):
            stats += f"  {indicator}: {count} files\n"
            
        self.stats_text.insert(tk.END, stats)
        
    def clear_results(self):
        """Clear all results"""
        self.results = []
        self.summary_text.delete(1.0, tk.END)
        self.timeline_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        
        # Clear tree
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
            
        self.progress_bar.config(value=0)
        self.progress_var.set("Ready to scan system...")
        
    def export_results(self):
        """Export results to JSON file"""
        if not self.results:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Scan Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                export_data = {
                    'scan_info': {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'total_files': len(self.results),
                        'scan_path': self.scan_path_var.get(),
                        'tool_version': '1.0.0'
                    },
                    'results': self.results
                }
                
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                    
                messagebox.showinfo("Success", f"Results exported to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

def main():
    """Main function"""
    root = tk.Tk()
    app = SystemTimestompScanner(root)
    root.mainloop()

if __name__ == '__main__':
    main()
