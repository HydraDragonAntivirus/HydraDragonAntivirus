import re

# Dosya adları
input_file = 'Domains.txt'
output_file_filtered = 'DomainsUpdated.txt'
output_file_unwanted = 'ContainsUnWanted.txt'

# Domains.txt dosyasını aç ve oku
with open(input_file, 'r') as file:
    lines = file.readlines()

# Satırları filtrele ve ayır
filtered_lines = [line for line in lines if '/' not in line]
unwanted_lines = [line for line in lines if '/' in line]

# DomainsUpdated.txt dosyasına yaz
with open(output_file_filtered, 'w') as file:
    file.writelines(filtered_lines)

# ContainsUnWanted.txt dosyasına yaz
with open(output_file_unwanted, 'w') as file:
    file.writelines(unwanted_lines)

print("/ karakteri içeren satırlar ContainsUnWanted.txt dosyasına, / karakteri içermeyen satırlar DomainsUpdated.txt dosyasına yazıldı.")