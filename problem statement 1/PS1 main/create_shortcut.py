#!/usr/bin/env python3
"""
Create desktop shortcut for GUI application
"""

import os
import sys
import subprocess
from pathlib import Path

def create_desktop_shortcut():
    """Create desktop shortcut for the GUI"""
    try:
        # Get current directory and desktop
        current_dir = os.path.dirname(os.path.abspath(__file__))
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        
        # Shortcut paths
        shortcut_path = os.path.join(desktop, "Timestomping Detector.lnk")
        python_exe = sys.executable
        gui_script = os.path.join(current_dir, "gui_detector.py")
        
        # Create VBScript to make shortcut
        vbs_script = f'''
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{shortcut_path}"
Set oLink = oWS.CreateShortcut(sLinkFile)
    oLink.TargetPath = "{python_exe}"
    oLink.Arguments = "{gui_script}"
    oLink.WorkingDirectory = "{current_dir}"
    oLink.Description = "Timestomping Detection Tool"
    oLink.IconLocation = "shell32.dll,13"
oLink.Save
'''
        
        # Save VBScript
        vbs_path = os.path.join(current_dir, "create_shortcut.vbs")
        with open(vbs_path, 'w') as f:
            f.write(vbs_script)
            
        # Run VBScript
        subprocess.run(['cscript', '//NoLogo', vbs_path], check=True)
        
        # Clean up
        os.remove(vbs_path)
        
        print(f"✅ Desktop shortcut created: {shortcut_path}")
        print(f"🚀 You can now launch the GUI from your desktop!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating shortcut: {e}")
        return False

def main():
    """Main function"""
    print("🔗 Creating Desktop Shortcut")
    print("=" * 30)
    
    if create_desktop_shortcut():
        print("\n✅ Success! Desktop shortcut created.")
        print("You can now run the Timestomping Detection Tool from your desktop.")
    else:
        print("\n❌ Failed to create desktop shortcut.")
        print("You can still run the tool manually with: python gui_detector.py")
    
    input("\n👆 Press Enter to exit...")

if __name__ == '__main__':
    main()
