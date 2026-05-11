import os
import shutil

def overwrite_file(file_path, wipe_level):
    try:
        passes = 3 if wipe_level != "Basic" else 1
        size = os.path.getsize(file_path)
        with open(file_path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
    except:
        pass

def simulate_wipe(folder_path, wipe_level="Basic"):
    folder_path = folder_path.strip()
    deleted_files = []
    deleted_folders = 0

    # First delete files
    for root, dirs, files in os.walk(folder_path, topdown=False):
        for file in files:
            full_path = os.path.join(root, file)
            overwrite_file(full_path, wipe_level)
            try:
                os.remove(full_path)
                print(f"DEBUG: Deleted file {full_path}")
                deleted_files.append(full_path)
            except Exception as e:
                print(f"DEBUG: Failed to delete {full_path}: {e}")
                pass
                
        # Then remove empty folders
        for directory in dirs:
            dir_path = os.path.join(root, directory)
            try:
                os.rmdir(dir_path)
                deleted_folders += 1
            except:
                pass

    # Finally, attempt to remove the root folder itself
    import time
    import subprocess
    try:
        if os.path.exists(folder_path):
            # Small delay to allow file handles to close
            time.sleep(0.5)
            try:
                shutil.rmtree(folder_path)
                deleted_folders += 1
            except:
                # If shutil fails, try OS-specific aggressive deletion
                try:
                    if os.name == 'nt':
                        # Windows /s removes all directories and files, /q is quiet mode
                        subprocess.run(['cmd', '/c', 'rd', '/s', '/q', folder_path], check=True)
                    else:
                        # Linux/Mac aggressive remove
                        subprocess.run(['rm', '-rf', folder_path], check=True)
                    deleted_folders += 1
                except:
                    # Last fallback
                    if os.path.exists(folder_path):
                        os.rmdir(folder_path)
                        deleted_folders += 1
    except:
        pass

    return {
        "status": "completed",
        "deleted_count": len(deleted_files),
        "deleted_files": deleted_files,
        "deleted_folders_count": deleted_folders,
        "details": f"{len(deleted_files)} files and {deleted_folders} folders wiped via {wipe_level} pattern."
    }

def setup_live_sandbox(folder_name="TestFolder"):
    """
    Creates a sandbox environment with dummy sensitive data for testing.
    Returns the absolute path to the sandbox.
    """
    path = os.path.abspath(folder_name)
    if os.path.exists(path):
        shutil.rmtree(path)
    
    os.makedirs(path)
    
    # Create some dummy files
    files = {
        "passwords.txt": "admin:password123\nuser:secret_access",
        "config.json": '{"api_key": "TS-SK-99212X", "env": "prod"}',
        "readme.txt": "This is a public file with no sensitive info.",
        "subfolder/keys.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA75...",
        "subfolder/data.csv": "id,name,ssn\n1,John Doe,123-456-7890"
    }
    
    for filename, content in files.items():
        file_path = os.path.join(path, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(content)
            
    return path