#!/usr/bin/env python3
"""
Test intelligent timestomping detection with dynamic thresholds
"""

import os
import time
import subprocess
from pathlib import Path

def test_intelligent_detection():
    """Test intelligent timestomping detection"""
    print("🧪 TESTING INTELLIGENT TIMESTOMPING DETECTION")
    print("=" * 60)
    
    # Import monitor
    from live_monitor import LiveTimestompMonitor
    
    # Create monitor
    monitor = LiveTimestompMonitor()
    
    # Configure to monitor all file types
    monitor.set_monitored_extensions(set())
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
        
        # Test 1: Normal timezone difference (should be low risk)
        print("\n🧪 Test 1: Normal timezone difference")
        normal_file = "E:\\normal_file.txt"
        with open(normal_file, 'w') as f:
            f.write("Normal file")
        time.sleep(3)  # Let monitor see it
        
        # Test 2: Suspicious timestomping (should be high risk)
        print("\n🧪 Test 2: Suspicious timestomping (2 years ago)")
        suspicious_file = "E:\\suspicious_file.txt"
        with open(suspicious_file, 'w') as f:
            f.write("Suspicious file")
        time.sleep(3)  # Let monitor see it
        
        # Timestomp to 2 years ago
        old_time = "01/01/2022 10:00:00"
        ps_command = f'(Get-Item "{suspicious_file}").CreationTime = "{old_time}"'
        
        result = subprocess.run(['powershell', '-Command', ps_command], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Suspicious file timestomped to 2022")
        else:
            print(f"❌ Error timestomping: {result.stderr}")
        
        # Test 3: Medium timestomping (should be medium risk)
        print("\n🧪 Test 3: Medium timestomping (12 hours ago)")
        medium_file = "E:\\medium_file.txt"
        with open(medium_file, 'w') as f:
            f.write("Medium file")
        time.sleep(3)  # Let monitor see it
        
        # Timestomp to 12 hours ago
        medium_time = (datetime.datetime.now() - datetime.timedelta(hours=12)).strftime("%m/%d/%Y %H:%M:%S")
        ps_command = f'(Get-Item "{medium_file}").CreationTime = "{medium_time}"'
        
        result = subprocess.run(['powershell', '-Command', ps_command], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Medium file timestomped to 12 hours ago")
        else:
            print(f"❌ Error timestomping: {result.stderr}")
        
        # Wait for all detections
        print("\n⏳ Waiting for detections...")
        time.sleep(8)
        
        # Display results
        if monitor.alerts:
            print(f"\n🚨 DETECTED {len(monitor.alerts)} ALERT(S):")
            for alert in monitor.alerts:
                print(f"\n📁 File: {os.path.basename(alert['file_path'])}")
                print(f"⚠️  Risk: {alert['risk_level'].upper()} (Score: {alert['risk_score']})")
                print(f"🔄 Event: {alert['event_type']}")
                if alert['discrepancies']:
                    for disc in alert['discrepancies']:
                        print(f"   • {disc}")
        else:
            print("❌ No alerts detected")
        
        # Cleanup
        for file in [normal_file, suspicious_file, medium_file]:
            try:
                os.unlink(file)
                print(f"🧹 Cleaned up: {file}")
            except:
                pass
        
        # Stop monitoring
        monitor.stop_monitoring()
        print("⏹️ Monitoring stopped")
        
        # Export results
        if monitor.alerts:
            filename = monitor.export_alerts()
            print(f"📄 Test results exported to: {filename}")
        
    else:
        print("❌ Failed to start monitoring")

if __name__ == '__main__':
    import datetime
    test_intelligent_detection()
