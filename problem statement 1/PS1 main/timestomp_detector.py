#!/usr/bin/env python3
"""
Timestomping Detection Tool
Main detection engine that combines MFT analysis and USN Journal parsing
- MFT analysis: Reads directly from live NTFS filesystem
- USN Journal: Queries live Windows API for transaction records
"""

import json
import os
import sys
import argparse
import datetime
from typing import Dict, List, Optional
from pathlib import Path

# Import live disk analysis components
from mft_analyzer import MFTAnalyzer
from usn_parser import USNJournalParser

class TimestompDetector:
    """Main timestomping detection engine"""
    
    def __init__(self, target_path: str, volume_path: str = None):
        """
        Initialize the detector
        
        Args:
            target_path: Path to scan (directory or file)
            volume_path: Volume path for USN journal (e.g., "C:")
        """
        self.target_path = target_path
        self.volume_path = volume_path or self._extract_volume_path(target_path)
        
        self.mft_analyzer = MFTAnalyzer()
        self.usn_parser = USNJournalParser(self.volume_path)
        
        self.results = {
            'scan_info': {
                'target_path': target_path,
                'volume_path': self.volume_path,
                'scan_time': datetime.datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'analysis_type': 'Live NTFS filesystem'
            },
            'files_analyzed': 0,
            'suspicious_files': [],
            'high_risk_files': [],
            'summary': {}
        }
        
    def _extract_volume_path(self, path: str) -> str:
        """Extract volume path from file path"""
        if len(path) >= 2 and path[1] == ':':
            return path[0].upper()
        return 'C'  # Default to C: drive
        
    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a single file for timestomping
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Analysis results for the file
        """
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
        print(f"Analyzing MFT timestamps for: {file_path}")
        mft_data = self.mft_analyzer.extract_timestamps(file_path)
        file_result['mft_analysis'] = mft_data
        
        # USN Journal Analysis
        print(f"Analyzing USN Journal for: {os.path.basename(file_path)}")
        filename = os.path.basename(file_path)
        usn_events = self.usn_parser.find_file_creation_events(filename, max_hours=24)
        file_result['usn_analysis'] = {
            'creation_events': usn_events,
            'event_count': len(usn_events)
        }
        
        # Risk Assessment
        file_result['risk_assessment'] = self._assess_risk(file_result)
        
        return file_result
        
    def _assess_risk(self, file_result: Dict) -> Dict:
        """
        Assess risk level based on MFT and USN analysis
        
        Args:
            file_result: File analysis results
            
        Returns:
            Risk assessment
        """
        risk_score = 0
        indicators = []
        
        # Check MFT discrepancies
        mft_analysis = file_result.get('mft_analysis', {})
        discrepancies = mft_analysis.get('discrepancies', [])
        
        if discrepancies:
            risk_score += len(discrepancies) * 10
            indicators.append(f"MFT timestamp discrepancies: {len(discrepancies)}")
            
        # Check USN vs MFT timestamps
        usn_analysis = file_result.get('usn_analysis', {})
        creation_events = usn_analysis.get('creation_events', [])
        
        if creation_events:
            # Get latest creation event
            latest_event = creation_events[-1]
            usn_timestamp = latest_event.get('timestamp')
            
            if usn_timestamp:
                usn_time = datetime.datetime.fromisoformat(usn_timestamp)
                
                # Compare with SI creation time
                si_timestamps = mft_analysis.get('si_timestamps', {})
                si_creation = si_timestamps.get('creation')
                
                if si_creation:
                    si_time = datetime.datetime.fromisoformat(si_creation)
                    
                    # Check if SI time is significantly earlier than USN time
                    time_diff = (usn_time - si_time).total_seconds()
                    
                    if time_diff > 3600:  # More than 1 hour difference
                        risk_score += 50
                        indicators.append(f"SI creation time {time_diff/3600:.1f} hours earlier than USN journal")
                        
                        # High risk if difference is more than 24 hours
                        if time_diff > 86400:
                            risk_score += 50
                            indicators.append("Major timestamp discrepancy detected (>24 hours)")
                            
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
        
    def scan_directory(self, directory_path: str) -> None:
        """
        Scan directory for timestomped files
        
        Args:
            directory_path: Directory to scan
        """
        print(f"Scanning directory: {directory_path}")
        
        try:
            # Walk through directory
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Analyze file
                        file_result = self.analyze_file(file_path)
                        self.results['files_analyzed'] += 1
                        
                        # Add to suspicious files if not low risk
                        if file_result['risk_assessment']['risk_level'] != 'low':
                            self.results['suspicious_files'].append(file_result)
                            
                            # Add to high risk files
                            if file_result['risk_assessment']['risk_level'] == 'high':
                                self.results['high_risk_files'].append(file_result)
                                
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {e}")
                        continue
                        
        except Exception as e:
            print(f"Error scanning directory: {e}")
            
    def generate_summary(self) -> Dict:
        """Generate analysis summary"""
        summary = {
            'total_files': self.results['files_analyzed'],
            'suspicious_count': len(self.results['suspicious_files']),
            'high_risk_count': len(self.results['high_risk_files']),
            'risk_distribution': {
                'low': 0,
                'medium': 0,
                'high': 0
            }
        }
        
        # Calculate risk distribution
        for file_result in self.results['suspicious_files']:
            risk_level = file_result['risk_assessment']['risk_level']
            summary['risk_distribution'][risk_level] += 1
            
        # Add low risk count
        summary['risk_distribution']['low'] = (
            summary['total_files'] - 
            summary['risk_distribution']['medium'] - 
            summary['risk_distribution']['high']
        )
        
        self.results['summary'] = summary
        return summary
        
    def save_report(self, output_path: str) -> None:
        """
        Save analysis report to JSON file
        
        Args:
            output_path: Path to save the report
        """
        try:
            # Generate summary
            self.generate_summary()
            
            # Save report
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
                
            print(f"Report saved to: {output_path}")
            
        except Exception as e:
            print(f"Error saving report: {e}")
            
    def print_summary(self) -> None:
        """Print analysis summary to console"""
        summary = self.generate_summary()
        
        print("\n" + "="*60)
        print("TIMESTOMPING DETECTION SUMMARY")
        print("="*60)
        print(f"Total files analyzed: {summary['total_files']}")
        print(f"Suspicious files: {summary['suspicious_count']}")
        print(f"High risk files: {summary['high_risk_count']}")
        print(f"Risk distribution:")
        print(f"  - Low risk: {summary['risk_distribution']['low']}")
        print(f"  - Medium risk: {summary['risk_distribution']['medium']}")
        print(f"  - High risk: {summary['risk_distribution']['high']}")
        
        if self.results['high_risk_files']:
            print("\nHIGH RISK FILES:")
            print("-" * 40)
            for file_result in self.results['high_risk_files'][:5]:  # Show first 5
                print(f"File: {file_result['file_path']}")
                print(f"Risk Score: {file_result['risk_assessment']['risk_score']}")
                indicators = file_result['risk_assessment']['indicators']
                for indicator in indicators:
                    print(f"  - {indicator}")
                print()
                
        print("="*60)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Detect timestomping on NTFS file systems')
    parser.add_argument('--target', required=True, help='Target path to scan')
    parser.add_argument('--output', help='Output JSON report path')
    parser.add_argument('--volume', help='Volume path for USN journal (e.g., C:)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate target path
    if not os.path.exists(args.target):
        print(f"Error: Target path does not exist: {args.target}")
        sys.exit(1)
        
    # Initialize detector
    detector = TimestompDetector(args.target, args.volume)
    
    # Scan target
    if os.path.isfile(args.target):
        # Analyze single file
        file_result = detector.analyze_file(args.target)
        detector.results['files_analyzed'] = 1
        
        if file_result['risk_assessment']['risk_level'] != 'low':
            detector.results['suspicious_files'].append(file_result)
            
        if file_result['risk_assessment']['risk_level'] == 'high':
            detector.results['high_risk_files'].append(file_result)
            
    else:
        # Scan directory
        detector.scan_directory(args.target)
        
    # Print summary
    detector.print_summary()
    
    # Save report if requested
    if args.output:
        detector.save_report(args.output)
        
    # Exit with appropriate code
    if detector.results['high_risk_files']:
        print("\n⚠️  HIGH RISK FILES DETECTED - Possible timestomping!")
        sys.exit(2)
    elif detector.results['suspicious_files']:
        print("\n⚠️  Suspicious files detected")
        sys.exit(1)
    else:
        print("\n[OK] No timestomping detected")
        sys.exit(0)

if __name__ == '__main__':
    main()
