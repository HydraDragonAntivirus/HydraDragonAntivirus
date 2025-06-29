# Dosya adları
input_file = 'Domains.txt'
output_file_filtered = 'DomainsUpdated.txt'
output_file_nothing = 'ContainsNothing.txt'

# Domains.txt dosyasını aç ve oku
with open(input_file, 'r') as file:
    lines = file.readlines()

# Satırları filtrele ve ayır
filtered_lines = [line for line in lines if '.' in line]
nothing_lines = [line for line in lines if '.' not in line]

# DomainsUpdated.txt dosyasına yaz
with open(output_file_filtered, 'w') as file:
    file.writelines(filtered_lines)

# ContainsNothing.txt dosyasına yaz
with open(output_file_nothing, 'w') as file:
    file.writelines(nothing_lines)

print(". karakteri içeren satırlar DomainsUpdated.txt dosyasına, . karakteri içermeyen satırlar ContainsNothing.txt dosyasına yazıldı.")