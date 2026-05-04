import os

def overwrite_file(file_path):
    try:
        with open(file_path, "r+b") as f:
            f.write(os.urandom(os.path.getsize(file_path)))
    except:
        pass

def simulate_wipe(folder_path, wipe_level="Basic"):
    deleted = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)

            overwrite_file(full_path)

            try:
                os.remove(full_path)
                deleted.append(full_path)
            except:
                pass

    return {
        "status": "completed",
        "deleted_count": len(deleted),
        "details": f"{len(deleted)} files wiped"
    }