import os
import shutil
import platform

def perform_backup(file_paths, device_id, source_root):
    """
    User-Selected Backup Module.
    Copies selected file paths to a secure location, preserving structure.
    """
    backup_path = f"./cloud_storage/{device_id}/"
    
    try:
        os.makedirs(backup_path, exist_ok=True)
    except:
        backup_path = "./temp_backup/"
        os.makedirs(backup_path, exist_ok=True)

    moved_count = 0
    
    for source_file in file_paths:
        if os.path.exists(source_file):
            # Calculate relative path to preserve structure
            rel_path = os.path.relpath(source_file, source_root)
            dest_file = os.path.join(backup_path, rel_path)
            
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(dest_file), exist_ok=True)
            
            try:
                shutil.copy2(source_file, dest_file) # Use copy instead of move to be safe
                moved_count += 1
            except Exception as e:
                print(f"Backup failed for {source_file}: {e}")
                continue

    return moved_count, backup_path
