import os
import sys
import PyInstaller.__main__
import customtkinter

def build():
    # Configure CustomTkinter assets path to include in the binary bundle
    ctk_path = os.path.dirname(customtkinter.__file__)
    
    # Check OS path separator for PyInstaller --add-data argument
    separator = ";" if os.name == "nt" else ":"

    print("[*] Starting PyInstaller Standalone Build for HydraDragon EDR Dashboard...")
    
    PyInstaller.__main__.run([
        'hydradragon/ui_app.py',
        '--name=HydraDragon_EDR_Dashboard',
        '--windowed',         # Hide command prompt window background
        '--onefile',          # Generate a single executable
        '--clean',            # Clean PyInstaller cache
        
        # Include CustomTkinter resources
        f'--add-data={ctk_path}{separator}customtkinter/',
        
        # Explicit hidden imports to prevent runtime crashes (Graceful fallback integration)
        '--hidden-import=asyncio',
        '--hidden-import=psutil',
        '--hidden-import=PIL',
        '--hidden-import=ctypes',
        '--hidden-import=json',
        '--hidden-import=queue',
        '--hidden-import=time',
        '--hidden-import=logging',
        '--hidden-import=threading',
        
        # HydraDragon Engine Backend Imports
        # Since these are loaded lazily inside the tkinter app to prevent circular loops,
        # PyInstaller analyzer cannot discover them automatically. We MUST force include them.
        '--hidden-import=hydradragon.antivirus_scripts.hydra_logger',
        '--hidden-import=hydradragon.antivirus_scripts.antivirus',
        '--hidden-import=hydradragon.engine',
    ])
    
    print("[+] Build Complete! Executable is located in the 'dist' directory.")

if __name__ == "__main__":
    build()
