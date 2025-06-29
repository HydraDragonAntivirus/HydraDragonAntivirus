invalid_lines = []

with open('Domains.txt', 'r') as domains_file, \
     open('trashpro.txt', 'a') as trashpro_file, \
     open('Domains_output.txt', 'w') as output_file:
     
    for line in domains_file:
        line = line.strip()
        if not line or not (line[0].isalpha() or line[0].isdigit()):
            invalid_lines.append(line)
            trashpro_file.write(line + '\n')
        else:
            output_file.write(line + '\n')

print("Operation completed. Invalid lines added to trashpro.txt. Remaining lines written to Domains_output.txt.")