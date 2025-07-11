# remove_duplicates.py
with open("antivirusprocesslist.txt", "r") as f:
    lines = f.readlines()

unique_lines = sorted(set(line.strip() for line in lines))

with open("cleaned_list.txt", "w") as f:
    for line in unique_lines:
        f.write(line + "\n")
