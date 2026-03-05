#!/usr/bin/env python3
"""
Test script specifically for PDF timestomping detection
"""

import os
import time
import subprocess
from pathlib import Path

def test_pdf_timestomping():
    """Test PDF timestomping detection"""
    print("🧪 TESTING PDF TIMESTOMPING DETECTION")
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
        
        # Wait for monitoring to initialize
        time.sleep(2)
        
        # Create a test PDF file
        test_pdf = "E:\\test.pdf"
        try:
            # Create a simple PDF file
            with open(test_pdf, 'wb') as f:
                f.write(b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n>>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n174\n%%EOF')
            
            print(f"📄 Created test PDF: {test_pdf}")
            
            # Wait a moment for file creation detection
            time.sleep(1)
            
            # Timestomp the PDF using PowerShell (same command you used)
            print("⏰ Timestomping PDF to 2021...")
            ps_command = f'(Get-Item "{test_pdf}").CreationTime = "01/01/2021 10:00:00"'
            
            result = subprocess.run(['powershell', '-Command', ps_command], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ PDF timestomped successfully")
            else:
                print(f"❌ Error timestomping PDF: {result.stderr}")
            
            # Wait for detection
            time.sleep(3)
            
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
                print("💡 This might be because:")
                print("   - The file change was too subtle")
                print("   - The monitoring needs more time")
                print("   - The file system didn't trigger the expected events")
            
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
    test_pdf_timestomping()
