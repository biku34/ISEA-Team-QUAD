#!/usr/bin/env python3
"""
Run Timestomping Detection Tool with Administrator Privileges
"""

import os
import sys
import ctypes
from tkinter import messagebox

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Restart the script with administrator privileges"""
    if is_admin():
        return True  # Already running as admin
        
    # Get the path to the current script
    script = os.path.abspath(sys.argv[0])
    
    # Build the command to run with elevated privileges
    params = ' '.join(sys.argv[1:])  # Pass through any additional arguments
    command = f'powershell -Command "Start-Process python -ArgumentList \'-Verb RunAs\' -FilePath \'{script}\' {params}"'
    
    print(f"🔐 Requesting administrator privileges...")
    print(f"📝 Command: {command}")
    
    try:
        os.system(command)
        return True
    except Exception as e:
        print(f"❌ Failed to elevate privileges: {e}")
        return False

def main():
    """Main function"""
    print("🔐 Timestomping Detection Tool - Administrator Access Check")
    print("=" * 60)
    
    if is_admin():
        print("✅ Already running with administrator privileges")
        print("🚀 Launching GUI...")
        
        # Import and run the GUI
        try:
            from gui_detector import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"❌ Failed to import GUI: {e}")
            input("Press Enter to exit...")
    else:
        print("❌ Administrator privileges required for USN Journal access")
        print("")
        print("📋 Why Administrator Access is Needed:")
        print("   • USN Journal requires system-level access")
        print("   • Real USN parser needs elevated privileges")
        print("   • Fallback parser will work without admin rights")
        print("")
        print("🔧 Options:")
        print("   1. Run with administrator privileges (recommended)")
        print("   2. Continue with fallback parser (limited functionality)")
        print("")
        
        choice = input("Choose option (1/2): ").strip()
        
        if choice == '1':
            print("\n🚀 Attempting to run with administrator privileges...")
            if run_as_admin():
                print("✅ Elevated successfully! GUI should open shortly...")
                input("Press Enter to exit...")
            else:
                print("❌ Failed to elevate privileges")
                input("Press Enter to exit...")
        elif choice == '2':
            print("\n🔄 Continuing with fallback USN parser...")
            print("⚠️  Note: USN Journal access will be limited")
            input("Press Enter to continue to GUI...")
            
            try:
                # Force use of fallback parser
                os.environ['FORCE_FALLBACK_USN'] = '1'
                from gui_detector import main as gui_main
                gui_main()
            except Exception as e:
                print(f"❌ Failed to start GUI: {e}")
                input("Press Enter to exit...")
        else:
            print("❌ Invalid choice")
            input("Press Enter to exit...")

if __name__ == '__main__':
    main()
