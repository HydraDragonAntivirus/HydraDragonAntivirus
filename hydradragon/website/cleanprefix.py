import os

# Get the current working directory
directory = os.getcwd()

# Iterate through files in the current directory
for filename in os.listdir(directory):
    # Check if the file starts with "cleaned_"
    if filename.startswith("cleaned_"):
        # Remove "cleaned_" from the filename
        new_name = filename[8:]  # Remove the first 8 characters
        # Create full paths for renaming
        old_path = os.path.join(directory, filename)
        new_path = os.path.join(directory, new_name)
        # Rename the file
        os.rename(old_path, new_path)
        print(f"{filename} -> {new_name}")

print("All files have been renamed successfully.")
