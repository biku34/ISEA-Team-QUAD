#!/usr/bin/env python3
"""
Realistic PDF timestomping test - creates file first, then timestomps it
"""

import os
import time
import subprocess
from pathlib import Path

def test_realistic_pdf_timestomping():
    """Test realistic PDF timestomping scenario"""
    print("🧪 TESTING REALISTIC PDF TIMESTOMPING")
    print("=" * 60)
    
    # Import the monitor
    from live_monitor import LiveTimestompMonitor
    
    # Create monitor
    monitor = LiveTimestompMonitor()
    
    # Configure to monitor all file types
    monitor.set_monitored_extensions(set())  # Empty set = all files
    print("📁 Configured to monitor ALL file types")
    
    # Add E: drive to monitoring
    monitor.add_monitor_path("E:\\")
    print("📁 Monitoring E:\\ drive")
    
    # Start monitoring
    print("🔴 Starting live monitoring...")
    if monitor.start_monitoring():
        print("✅ Monitoring started successfully")
        
        # Create a test PDF file first
        test_pdf = "E:\\test_real.pdf"
        try:
            # Create a simple PDF file
            with open(test_pdf, 'wb') as f:
                f.write(b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n>>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n174\n%%EOF')
            
            print(f"📄 Created test PDF: {test_pdf}")
            
            # Wait for monitor to see the file and cache its timestamps
            print("⏳ Waiting for monitor to cache file timestamps...")
            time.sleep(8)  # Wait for periodic scan to run
            
            # Now timestomp the PDF using PowerShell
            print("⏰ Timestomping PDF to 2021...")
            ps_command = f'(Get-Item "{test_pdf}").CreationTime = "01/01/2021 10:00:00"'
            
            result = subprocess.run(['powershell', '-Command', ps_command], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ PDF timestomped successfully")
            else:
                print(f"❌ Error timestomping PDF: {result.stderr}")
            
            # Wait for detection
            print("⏳ Waiting for detection...")
            time.sleep(8)  # Wait for next periodic scan
            
            # Check for alerts
            if monitor.alerts:
                print(f"\n🚨 DETECTED {len(monitor.alerts)} ALERT(S):")
                for alert in monitor.alerts:
                    print(f"   • File: {alert['file_path']}")
                    print(f"     Risk: {alert['risk_level']} (Score: {alert['risk_score']})")
                    print(f"     Event: {alert['event_type']}")
                    if alert['discrepancies']:
                        for disc in alert['discrepancies']:
                            print(f"     - {disc}")
            else:
                print("❌ No alerts detected")
                print("💡 Let's check if the file actually got timestomped...")
                
                # Check the actual file timestamps
                try:
                    stat_info = os.stat(test_pdf)
                    creation_time = time.ctime(stat_info.st_ctime)
                    modification_time = time.ctime(stat_info.st_mtime)
                    print(f"📅 File creation time: {creation_time}")
                    print(f"📅 File modification time: {modification_time}")
                    
                    # Also analyze with our MFT analyzer
                    analysis = monitor.mft_analyzer.extract_timestamps(test_pdf)
                    if 'si_timestamps' in analysis:
                        si_times = analysis['si_timestamps']
                        print(f"🔍 SI Creation: {si_times.get('creation', 'N/A')}")
                        print(f"🔍 SI Modification: {si_times.get('modification', 'N/A')}")
                    
                    if 'discrepancies' in analysis and analysis['discrepancies']:
                        print(f"🔍 MFT discrepancies: {analysis['discrepancies']}")
                        
                except Exception as e:
                    print(f"❌ Error checking file timestamps: {e}")
            
            # Cleanup
            try:
                os.unlink(test_pdf)
                print(f"\n🧹 Cleaned up test file: {test_pdf}")
            except:
                pass
            
            # Stop monitoring
            monitor.stop_monitoring()
            print("⏹️ Monitoring stopped")
            
            # Export results
            if monitor.alerts:
                filename = monitor.export_alerts()
                print(f"📄 Test results exported to: {filename}")
        
        except Exception as e:
            print(f"❌ Error during test: {e}")
            monitor.stop_monitoring()
        
    else:
        print("❌ Failed to start monitoring")

if __name__ == '__main__':
    test_realistic_pdf_timestomping()
