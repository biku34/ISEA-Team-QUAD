#!/usr/bin/env python3
"""
Quick CLI System Scanner for Timestomping Detection
Fast command-line system scan with timestamp correlation
- MFT analysis: Reads directly from live NTFS filesystem
- USN Journal: Queries live Windows API for transaction records
"""

import os
import sys
import json
import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import live disk analysis components
from mft_analyzer import MFTAnalyzer
from usn_parser import USNJournalParser

class QuickSystemScanner:
    """Quick CLI system scanner"""
    
    def __init__(self):
        self.mft_analyzer = MFTAnalyzer()
        self.usn_parser = USNJournalParser(self._get_volume_path())
        self.results = []
        
    def _get_volume_path(self):
        """Get system volume path"""
        current_dir = os.getcwd()
        if len(current_dir) >= 2 and current_dir[1] == ':':
            return current_dir[0].upper()
        return 'C'
        
    def scan_directory(self, scan_path, file_types=['exe', 'dll', 'sys'], max_files=1000):
        """Scan directory for timestomping"""
        print(f"🔍 Starting quick scan: {scan_path}")
        print(f"📁 Looking for: {', '.join(['.' + ext for ext in file_types])}")
        print(f"📊 Max files: {max_files}")
        print("=" * 60)
        
        # Get files
        files_to_scan = []
        try:
            for root, dirs, files in os.walk(scan_path):
                for file in files:
                    if len(files_to_scan) >= max_files:
                        break
                        
                    if any(file.lower().endswith('.' + ext) for ext in file_types):
                        files_to_scan.append(os.path.join(root, file))
                        
                if len(files_to_scan) >= max_files:
                    break
                    
        except Exception as e:
            print(f"❌ Error walking directory: {e}")
            return
            
        print(f"📋 Found {len(files_to_scan)} files to scan")
        print()
        
        # Scan files
        suspicious_files = []
        scanned_count = 0
        
        for i, file_path in enumerate(files_to_scan):
            try:
                print(f"🔍 [{i+1:4d}/{len(files_to_scan):4d}] Scanning: {os.path.basename(file_path)}")
                
                # Analyze file
                result = self.analyze_file(file_path)
                if result:
                    self.results.append(result)
                    risk_level = result['risk_assessment']['risk_level']
                    risk_score = result['risk_assessment']['risk_score']
                    
                    if risk_level in ['medium', 'high']:
                        suspicious_files.append(result)
                        print(f"⚠️  {risk_level.upper()} RISK (Score: {risk_score})")
                        
                        # Show key indicators
                        indicators = result['risk_assessment']['indicators']
                        for indicator in indicators[:3]:
                            print(f"    • {indicator}")
                            
                        # Show timestamp correlation
                        self.show_timestamp_correlation(result)
                        print()
                    else:
                        print(f"✅ Low risk (Score: {risk_score})")
                        
                scanned_count += 1
                
            except Exception as e:
                print(f"❌ Error scanning {file_path}: {e}")
                continue
                
        # Summary
        self.print_summary(scanned_count, suspicious_files)
        
        # Export results
        if suspicious_files:
            self.export_results(scan_path)
            
    def analyze_file(self, file_path):
        """Analyze single file"""
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
            return None
            
    def assess_risk(self, mft_data, usn_events, filename):
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
        
    def show_timestamp_correlation(self, result):
        """Show timestamp correlation for suspicious file"""
        filename = result['filename']
        mft = result['mft_analysis']
        usn = result['usn_analysis']
        
        print("    📅 Timestamp Correlation:")
        
        # Show MFT timestamps
        si_time = mft.get('si_timestamps', {}).get('creation')
        fn_time = mft.get('fn_timestamps', {}).get('creation')
        
        if si_time:
            print(f"       $SI (Standard Info): {si_time}")
        if fn_time:
            print(f"       $FN (File Name):     {fn_time}")
            
        # Show USN events
        if usn.get('creation_events'):
            for event in usn['creation_events'][:2]:
                print(f"       USN Journal:        {event.get('timestamp')} ({', '.join(event.get('reasons', []))})")
                
        # Highlight discrepancies
        if si_time and fn_time and si_time != fn_time:
            try:
                si_dt = datetime.datetime.fromisoformat(si_time)
                fn_dt = datetime.datetime.fromisoformat(fn_time)
                diff = abs((fn_dt - si_dt).total_seconds())
                print(f"       ⚠️  Discrepancy:     {diff/3600:.1f} hours")
            except:
                pass
                
    def print_summary(self, scanned_count, suspicious_files):
        """Print scan summary"""
        print("=" * 60)
        print("📊 SCAN SUMMARY")
        print("=" * 60)
        
        total = len(self.results)
        high_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'high')
        medium_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'medium')
        low_risk = sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'low')
        
        print(f"📁 Files Scanned: {scanned_count}")
        print(f"📁 Files Analyzed: {total}")
        print(f"🔴 High Risk: {high_risk}")
        print(f"🟡 Medium Risk: {medium_risk}")
        print(f"🟢 Low Risk: {low_risk}")
        print(f"⚠️  Suspicious Files: {high_risk + medium_risk}")
        print(f"📈 Suspicious Rate: {(high_risk + medium_risk)/total*100:.1f}%" if total > 0 else "📈 Suspicious Rate: 0%")
        
        if suspicious_files:
            print()
            print("🎯 TOP SUSPICIOUS FILES:")
            for i, result in enumerate(suspicious_files[:5], 1):
                filename = result['filename']
                score = result['risk_assessment']['risk_score']
                level = result['risk_assessment']['risk_level'].upper()
                print(f"  {i}. {filename} - {level} (Score: {score})")
                
    def export_results(self, scan_path):
        """Export results to JSON"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"timestomp_scan_{timestamp}.json"
        
        try:
            export_data = {
                'scan_info': {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'scan_path': scan_path,
                    'total_files': len(self.results),
                    'tool_version': '1.0.0',
                    'analysis_type': 'Live NTFS filesystem'
                },
                'summary': {
                    'high_risk': sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'high'),
                    'medium_risk': sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'medium'),
                    'low_risk': sum(1 for r in self.results if r['risk_assessment']['risk_level'] == 'low'),
                    'suspicious_rate': (sum(1 for r in self.results if r['risk_assessment']['risk_level'] in ['high', 'medium'])) / len(self.results) * 100 if self.results else 0
                },
                'results': self.results
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
                
            print(f"📄 Results exported to: {filename}")
            
        except Exception as e:
            print(f"❌ Failed to export results: {e}")

def main():
    """Main function"""
    print("🔍 QUICK SYSTEM TIMESTOMPING SCANNER")
    print("=" * 60)
    
    # Get scan path
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
    else:
        scan_path = input("Enter directory to scan (e.g., C:\\Windows): ").strip()
        
    if not os.path.exists(scan_path):
        print(f"❌ Directory does not exist: {scan_path}")
        return
        
    # Get file types
    print("\n📁 Select file types to scan:")
    print("1. Executables only (.exe, .dll, .sys)")
    print("2. Documents only (.doc, .pdf, .txt)")
    print("3. All files (slower)")
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == '1':
        file_types = ['exe', 'dll', 'sys', 'scr']
    elif choice == '2':
        file_types = ['doc', 'docx', 'pdf', 'txt']
    else:
        file_types = ['*']  # All files
        
    # Get max files
    max_files = input("Max files to scan (default 500): ").strip()
    try:
        max_files = int(max_files) if max_files else 500
    except:
        max_files = 500
        
    print()
    
    # Start scan
    scanner = QuickSystemScanner()
    
    if file_types == ['*']:
        scanner.scan_directory(scan_path, file_types=[], max_files=max_files)
    else:
        scanner.scan_directory(scan_path, file_types=file_types, max_files=max_files)

if __name__ == '__main__':
    main()
