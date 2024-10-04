#
# (c) J~Net 2024
#
# python run.py
#
# pip install PyGObject
# pip install --upgrade pip setuptools
#
#
import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

class DuplicateFileChecker:
    def __init__(self):
        try:
            self.root=tk.Tk()
            self.root.title("Duplicate File Remover")

            self.recursive=tk.BooleanVar(value=False)
            self.auto_remove=tk.BooleanVar(value=True)

            tk.Checkbutton(self.root, text="Recursive Scan", variable=self.recursive).pack(pady=5)
            tk.Checkbutton(self.root, text="Auto Remove Duplicates", variable=self.auto_remove).pack(pady=5)

            tk.Button(self.root, text="Edit Scan List", command=self.edit_scan_list).pack(pady=10)
            tk.Button(self.root, text="Add to Scan List", command=self.add_to_scan_list).pack(pady=10)
            tk.Button(self.root, text="Remove from Scan List", command=self.remove_from_scan_list).pack(pady=10)
            tk.Button(self.root, text="Scan for Duplicates", command=self.scan_for_duplicates).pack(pady=10)
            tk.Button(self.root, text="About", command=self.show_about).pack(pady=10)

            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.scan_directories=[]

            self.load_scan_list()
            self.root.mainloop()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during initialization: {str(e)}")
            self.root.quit()

    def on_closing(self):
        self.save_scan_list()
        self.root.destroy()

    def save_scan_list(self):
        with open("hashes.txt", "w") as f:
            for directory in self.scan_directories:
                f.write(f"{directory}\n")

    def load_scan_list(self):
        if os.path.exists("hashes.txt"):
            with open("hashes.txt", "r") as f:
                self.scan_directories=[line.strip() for line in f]

    def add_to_scan_list(self):
        directory=filedialog.askdirectory(title="Select Directory to Add")
        if directory and directory not in self.scan_directories:
            self.scan_directories.append(directory)

    def remove_from_scan_list(self):
        directory=simpledialog.askstring("Remove Directory", "Enter the directory to remove:")
        if directory in self.scan_directories:
            self.scan_directories.remove(directory)

    def edit_scan_list(self):
        edit_window=tk.Toplevel(self.root)
        edit_window.title("Edit Scan List")
        
        for dir in self.scan_directories:
            tk.Label(edit_window, text=dir).pack()

    def show_about(self):
        messagebox.showinfo("About", "Author: Jay @ J~Net 2024")

    def scan_for_duplicates(self):
        try:
            if not self.scan_directories:
                messagebox.showinfo("Info", "No directories to scan!")
                return

            total_duplicates_found=0
            total_removed=0
            seen_files={}  # Dictionary to track seen files across all directories

            # Process each directory and gather all image files
            for directory in self.scan_directories:
                if self.recursive.get():
                    for root, _, files in os.walk(directory):
                        duplicates_found, removed=self.check_files(root, files, seen_files)
                        total_duplicates_found += duplicates_found
                        total_removed += removed
                else:
                    files=[f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
                    duplicates_found, removed=self.check_files(directory, files, seen_files)
                    total_duplicates_found += duplicates_found
                    total_removed += removed

            if total_duplicates_found == 0:
                messagebox.showinfo("Duplicate Removal Complete", "No duplicates found.")
            else:
                messagebox.showinfo("Duplicate Removal Complete", 
                                    f"Total duplicates found: {total_duplicates_found}\nTotal removed: {total_removed}")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during scanning: {str(e)}")

    def check_files(self, directory, files, seen_files):
        duplicates_found=0
        removed=0

        # Supported image file extensions
        image_extensions=('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff')

        for filename in files:
            # Only process image files
            if not filename.lower().endswith(image_extensions):
                continue
            
            file_path=os.path.join(directory, filename)
            
            # Check if file exists before processing
            if not os.path.exists(file_path):
                print(f"File does not exist: {file_path}")  # Debug statement
                continue

            # Calculate hash for the file
            file_hash=self.calculate_hash(file_path)
            
            # Skip None hashes (in case of error)
            if file_hash is None:
                print(f"Skipping file due to hash error: {file_path}")  # Debug statement
                continue

            print(f"Processing {file_path} with hash {file_hash}")  # Debug statement

            if file_hash in seen_files:
                # Duplicate found
                print(f"Duplicate found: {file_path} (original: {seen_files[file_hash]})")  # Debug statement
                duplicates_found += 1
                if self.auto_remove.get():
                    print(f"Removing duplicate: {file_path}")  # Debug statement
                    os.remove(file_path)
                    removed += 1
            else:
                # Store the original file path with its hash
                seen_files[file_hash]=file_path

        return duplicates_found, removed

    def calculate_hash(self, filepath):
        hash_md5=hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {filepath}: {e}")
            return None  # Return None if there's an error in reading the file

if __name__ == "__main__":
    DuplicateFileChecker()

