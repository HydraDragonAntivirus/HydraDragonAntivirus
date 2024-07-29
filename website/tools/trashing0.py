input_file = "Domains.txt"
output_file = "Domains_output.txt"
trash_file = "trashing0.txt"

with open(input_file, 'r') as infile, \
     open(output_file, 'w') as outfile, \
     open(trash_file, 'w') as trash:
    for line in infile:
        line = line.strip()
        if '.' in line:
            outfile.write(line + '\n')
        else:
            trash.write(line + '\n')