import re

def extract_critical_command_lines(sigma_file, output_file):
    with open(sigma_file, 'r', encoding='latin-1') as file:
        lines = file.readlines()

    titles = []
    command_lines = []
    current_title = None
    capture_command_lines = False
    rule_started = False

    for line in lines:
        # Detect the start of a new Sigma rule
        title_match = re.match(r'^title:\s*(.*)', line)
        if title_match:
            if rule_started and current_title:
                # If a previous critical rule was processed, save its details
                titles.append(current_title)
                command_lines.append(current_command_lines)
            # Start capturing for the new rule
            current_title = title_match.group(1)
            current_command_lines = []
            rule_started = False
        
        # Detect if the current rule is critical
        if 'level: critical' in line:
            rule_started = True
        
        # Capture CommandLine entries only if the current rule is critical
        if rule_started and re.match(r'^\s*- .*', line):
            cmd_match = re.match(r'^\s*- (.*)', line)
            if cmd_match:
                command_line = cmd_match.group(1)
                if current_title:
                    current_command_lines.append(command_line)
        
        # Ensure to capture the last rule if it is critical
        if 'condition:' in line and rule_started:
            if current_title and current_command_lines:
                titles.append(current_title)
                command_lines.append(current_command_lines)
            rule_started = False

    # Write to output file
    with open(output_file, 'w', encoding='latin-1') as out_file:
        for title, cmds in zip(titles, command_lines):
            out_file.write(f"Title: {title}\n")
            for cmd in cmds:
                out_file.write(f"CommandLine: {cmd}\n")
            out_file.write("\n")

if __name__ == "__main__":
    sigma_file = 'allofcommandlinecritical.txt'  # Sigma file name
    output_file = 'allofcommandlinecritical_output.txt'
    extract_critical_command_lines(sigma_file, output_file)