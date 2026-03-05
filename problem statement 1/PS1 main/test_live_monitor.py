#!/usr/bin/env python3
"""
Test script for Live Timestomping Monitor
Demonstrates real-time detection capabilities
"""

import os
import time
import tempfile
import subprocess
from pathlib import Path

def create_test_file_with_timestomp():
    """Create a test file and timestomp it"""
    # Create temporary file
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(b"Fake executable content for testing")
        temp_file = f.name
    
    print(f"📁 Created test file: {temp_file}")
    
    # Timestomp the file using PowerShell
    try:
        # Set creation time to 1 year ago
        old_time = (time.time() - 365 * 24 * 3600)
        ps_command = f'''
        (Get-Item "{temp_file}").CreationTime = [datetime]::FromFileTime({int(old_time * 10000000)})
        '''
        
        subprocess.run(['powershell', '-Command', ps_command], capture_output=True)
        print("⏰ Timestomped file to 1 year ago")
        
    except Exception as e:
        print(f"❌ Error timestomping file: {e}")
    
    return temp_file

def test_live_monitor():
    """Test the live monitor with simulated timestomping"""
    print("🧪 TESTING LIVE TIMESTOMPING MONITOR")
    print("=" * 60)
    
    # Import the monitor
    from live_monitor import LiveTimestompMonitor
    
    # Create monitor
    monitor = LiveTimestompMonitor()
    
    # Add temp directory to monitoring
    temp_dir = tempfile.gettempdir()
    monitor.add_monitor_path(temp_dir)
    print(f"📁 Monitoring directory: {temp_dir}")
    
    # Start monitoring
    print("🔴 Starting live monitoring...")
    if monitor.start_monitoring():
        print("✅ Monitoring started successfully")
        
        # Wait a moment for monitoring to initialize
        time.sleep(2)
        
        # Create and timestomp test file
        print("\n🎭 Simulating timestomping attack...")
        test_file = create_test_file_with_timestomp()
        
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
            print("❌ No alerts detected (monitoring may need more time)")
        
        # Cleanup
        try:
            os.unlink(test_file)
            print(f"\n🧹 Cleaned up test file: {test_file}")
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
    test_live_monitor()
