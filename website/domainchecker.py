import re

# Dosya adları
input_file = 'Domains.txt'
output_file_filtered = 'DomainsUpdated.txt'
output_file_big_char = 'BigCharacter.txt'

# Domains.txt dosyasını aç ve oku
with open(input_file, 'r') as file:
    lines = file.readlines()

# Satırları filtrele ve ayır
filtered_lines = [line for line in lines if not re.search(r'[A-Z]', line)]
big_char_lines = [line for line in lines if re.search(r'[A-Z]', line)]

# DomainsUpdated.txt dosyasına yaz
with open(output_file_filtered, 'w') as file:
    file.writelines(filtered_lines)

# BigCharacter.txt dosyasına yaz
with open(output_file_big_char, 'w') as file:
    file.writelines(big_char_lines)

print("Büyük harf içeren satırlar BigCharacter.txt dosyasına, büyük harf içermeyen satırlar DomainsUpdated.txt dosyasına yazıldı.")