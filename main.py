import os

def list_files_recursive(path="."):
    files_info = {}
    for root, _, files in os.walk(path):
        sub_dir = files_info
        for part in root[len(path):].strip(os.sep).split(os.sep):
            sub_dir = sub_dir.setdefault(part, {})
        for file_name in files:
            file_path = os.path.join(root, file_name)
            sub_dir[file_name] = {
                "size": os.path.getsize(file_path)
            }
    return files_info

# Running the function and printing the output
print(list_files_recursive())