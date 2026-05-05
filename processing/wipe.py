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
    deleted_files = []
    deleted_folders = 0

    # First delete files
    for root, dirs, files in os.walk(folder_path, topdown=False):
        for file in files:
            full_path = os.path.join(root, file)
            overwrite_file(full_path, wipe_level)
            try:
                os.remove(full_path)
                deleted_files.append(full_path)
            except:
                pass
                
        # Then remove empty folders
        for directory in dirs:
            dir_path = os.path.join(root, directory)
            try:
                os.rmdir(dir_path)
                deleted_folders += 1
            except:
                pass

    return {
        "status": "completed",
        "deleted_count": len(deleted_files),
        "deleted_folders_count": deleted_folders,
        "details": f"{len(deleted_files)} files and {deleted_folders} folders wiped via {wipe_level} pattern."
    }