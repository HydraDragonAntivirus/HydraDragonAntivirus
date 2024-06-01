import os

def print_rules_with_include(directory):
    # Belirtilen dizindeki dosyaları listele
    for filename in os.listdir(directory):
        # Dosya adının 'rules' ile bitip bitmediğini kontrol et
        if filename.endswith('rules'):
            # include $RULE_PATH\ ekleyerek dosya adını oluştur
            include_statement = f"include $RULE_PATH\\{filename}"
            # Ekrana yazdır
            print(include_statement)

# Kullanmak istediğiniz klasör yolunu buraya yazın
directory_path = '.'

# Fonksiyonu çağırın
print_rules_with_include(directory_path)