input_file = "all.yar"  # Input file containing the code/comments
comments_file = "comment_lines3.txt"  # Output file for extracted comments
cleaned_file = "all_cleaned.yar"  # Output file with comments removed

with open(input_file, "r") as infile, \
     open(comments_file, "w") as outfile_comments, \
     open(cleaned_file, "w") as outfile_cleaned:

    for line in infile:
        if line.strip().startswith("// "):  # Extract comments starting with '// '
            outfile_comments.write(line)
        else:
            outfile_cleaned.write(line)  # Write non-comment lines to the cleaned file

print(f"Comment lines have been saved to {comments_file}")
print(f"Cleaned file without comments has been saved to {cleaned_file}")
