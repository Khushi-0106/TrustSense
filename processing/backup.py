import os
import shutil
import platform

def perform_backup(scan_result, device_id, source_root):
    """
    Optional Backup Module for TrustSense.
    Identifies and moves sensitive files to a local cloud simulation directory.
    """
    backup_path = f"./cloud_storage/{device_id}/"
    fallback_path = "./temp_backup/"
    
    try:
        os.makedirs(backup_path, exist_ok=True)
    except:
        backup_path = fallback_path
        os.makedirs(backup_path, exist_ok=True)

    moved_count = 0
    sensitive_extensions = ('.txt', '.pdf', '.docx')
    
    files_to_match = set(scan_result.get("files", []))
    
    for root, dirs, files in os.walk(source_root):
        for file in files:
            if file in files_to_match and file.lower().endswith(sensitive_extensions):
                source_file = os.path.join(root, file)
                
                # Calculate relative path to preserve structure
                rel_path = os.path.relpath(source_file, source_root)
                dest_file = os.path.join(backup_path, rel_path)
                
                # Ensure destination directory exists
                os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                
                try:
                    shutil.move(source_file, dest_file)
                    moved_count += 1
                except:
                    continue # Skip failures silently

    return moved_count, backup_path
