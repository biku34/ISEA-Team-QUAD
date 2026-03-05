#!/usr/bin/env python3
"""
Minimal GUI test for visibility
"""

import tkinter as tk
import time

def main():
    print("Creating GUI window...")
    
    # Create root window
    root = tk.Tk()
    root.title("TEST WINDOW - Should be visible")
    root.geometry("500x400+100+100")  # Position at 100,100
    
    # Force visibility
    root.lift()
    root.attributes('-topmost', True)
    root.focus_force()
    
    # Add a label to confirm it's working
    label = tk.Label(root, text="If you can see this, GUI is working!", 
                     font=('Arial', 16), bg='lightblue', fg='darkblue')
    label.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    # Add a button
    button = tk.Button(root, text="Close", command=root.quit, 
                      font=('Arial', 12), bg='red', fg='white')
    button.pack(pady=20)
    
    print("Window created. Check if visible...")
    
    # Show window for 5 seconds then close
    root.after(5000, root.quit)
    
    # Start mainloop
    root.mainloop()
    
    print("Window closed.")

if __name__ == '__main__':
    main()
