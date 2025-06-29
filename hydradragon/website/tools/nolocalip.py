import re

def is_local_ip(ip):
    # 192.168.x.x
    if re.match(r'^192\.168\.\d{1,3}\.\d{1,3}$', ip):
        return True
    # 10.x.x.x
    if re.match(r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return True
    # 172.16.x.x - 172.31.x.x
    if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$', ip):
        return True
    return False

def separate_local_ips(input_filename, output_filename):
    with open(input_filename, 'r') as infile:
        lines = infile.readlines()
    
    with open(input_filename, 'w') as infile, open(output_filename, 'w') as outfile:
        for line in lines:
            ip = line.strip()
            if is_local_ip(ip):
                outfile.write(line)
            else:
                infile.write(line)

# Kullanım
input_filename = 'IP_Addresses.txt'
output_filename = 'localip.txt'
separate_local_ips(input_filename, output_filename)