# Domains.txt dosyasını aç ve oku
with open('Domains.txt', 'r') as file:
    lines = file.readlines()

# # ile başlayan satırları filtrele ve diğer satırları sakla
problematic_lines = [line for line in lines if line.startswith('#')]
remaining_lines = [line for line in lines if not line.startswith('#')]

# Problematicwebsites.txt dosyasına yaz
with open('problematicwebsites.txt', 'w') as file:
    file.writelines(problematic_lines)

# Geri kalan satırları Domains.txt dosyasına geri yaz
with open('Domains.txt', 'w') as file:
    file.writelines(remaining_lines)