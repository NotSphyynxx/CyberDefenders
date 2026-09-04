import os
import re

def fix_images(base_dir):
    # Regex to find standard Markdown image links pointing to resources
    pattern1 = re.compile(r'\]\(/resources/')
    pattern2 = re.compile(r'\]\(resources/')
    
    repo_url = "](https://raw.githubusercontent.com/ChickenLoner/Write_It_UP/main/resources/"
    
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".md"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                new_content = pattern1.sub(repo_url, content)
                new_content = pattern2.sub(repo_url, new_content)
                
                if new_content != content:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    print(f"Fixed images in {file_path}")

if __name__ == "__main__":
    fix_images("Labs")
