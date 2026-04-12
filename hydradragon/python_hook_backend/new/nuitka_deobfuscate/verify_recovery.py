"""
verify_recovery.py - Analyze recovered .pyc files to find the SinqleBoY main code
and catalog all recovered modules.
"""
import marshal
import struct
from pathlib import Path
from collections import defaultdict

def main():
    root = Path('restore_deep_ultra')
    
    # 1. Count all .pyc files
    all_pyc = list(root.rglob('*.pyc'))
    print(f"[*] Total .pyc files recovered: {len(all_pyc)}")
    
    # 2. Find files with SinqleBoY references
    sinqle_files = []
    homeko_files = []
    main_modules = []
    all_co_filenames = defaultdict(list)
    
    for pyc_path in all_pyc:
        try:
            data = pyc_path.read_bytes()
            # Skip 16-byte header
            code_obj = marshal.loads(data[16:])
            if type(code_obj).__name__ != 'code':
                continue
            
            co_filename = getattr(code_obj, 'co_filename', '')
            co_name = getattr(code_obj, 'co_name', '')
            
            # Track all unique co_filename values
            all_co_filenames[co_filename].append(str(pyc_path.relative_to(root)))
            
            # Check for SinqleBoY
            if 'SinqleBoY' in co_filename or 'SinqleBoY' in co_name:
                sinqle_files.append((pyc_path, co_filename, co_name, len(data)))
            
            # Check for HomekoWorld
            if 'Homeko' in co_filename or 'homeko' in co_filename.lower():
                homeko_files.append((pyc_path, co_filename, co_name, len(data)))
                
            # Check for __main__ modules
            if co_name == '<module>' and ('SinqleBoY' in co_filename or 'Homeko' in co_filename or 'main' in co_filename.lower()):
                main_modules.append((pyc_path, co_filename, co_name, len(data)))
                
        except Exception:
            pass
    
    # 3. Report SinqleBoY findings
    print(f"\n[*] Files referencing 'SinqleBoY': {len(sinqle_files)}")
    for p, fn, cn, sz in sorted(sinqle_files, key=lambda x: -x[3])[:20]:
        print(f"  - {p.relative_to(root)} | co_filename={fn} | co_name={cn} | size={sz}")
    
    print(f"\n[*] Files referencing 'Homeko': {len(homeko_files)}")
    for p, fn, cn, sz in sorted(homeko_files, key=lambda x: -x[3])[:20]:
        print(f"  - {p.relative_to(root)} | co_filename={fn} | co_name={cn} | size={sz}")
    
    print(f"\n[*] Main/Entry modules: {len(main_modules)}")
    for p, fn, cn, sz in sorted(main_modules, key=lambda x: -x[3])[:20]:
        print(f"  - {p.relative_to(root)} | co_filename={fn} | co_name={cn} | size={sz}")
    
    # 4. Show top 20 largest .pyc files
    print(f"\n[*] Top 20 largest .pyc files:")
    largest = sorted(all_pyc, key=lambda p: p.stat().st_size, reverse=True)[:20]
    for p in largest:
        try:
            data = p.read_bytes()
            code_obj = marshal.loads(data[16:])
            co_fn = getattr(code_obj, 'co_filename', '?')
            co_nm = getattr(code_obj, 'co_name', '?')
            print(f"  - {p.stat().st_size:>8} bytes | {p.relative_to(root)} | co_filename={co_fn} | co_name={co_nm}")
        except:
            print(f"  - {p.stat().st_size:>8} bytes | {p.relative_to(root)} | (failed to parse)")
    
    # 5. Show unique co_filename paths that look like application code (not stdlib)
    print(f"\n[*] Unique co_filename paths (non-stdlib, application code):")
    app_paths = {}
    for co_fn, pyc_list in all_co_filenames.items():
        if not co_fn:
            continue
        # Filter out stdlib and site-packages
        lower = co_fn.lower()
        if any(x in lower for x in ['site-packages', 'lib\\python', 'lib/python', 'stdlib', 'numpy', 'scipy', 'win32', 'pycparser']):
            continue
        if any(x in lower for x in ['sinqle', 'homeko', 'sinqleboY', 'bot', 'macro', 'hack', 'cheat', 'auto', 'game']):
            app_paths[co_fn] = pyc_list
    
    for co_fn, pyc_list in sorted(app_paths.items()):
        print(f"  - {co_fn} -> {pyc_list[:3]}")

if __name__ == '__main__':
    main()
