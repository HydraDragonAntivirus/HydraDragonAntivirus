def filter_alert_lines(input_file_path, output_file_path):
    with open(input_file_path, 'r', encoding='utf-8') as infile, open(output_file_path, 'w', encoding='utf-8') as outfile:
        for line in infile:
            if line.startswith('alert'):
                outfile.write(line)

# Kullanım örneği
input_file = 'HIPS.rules'  # Giriş dosyasının yolu
output_file = 'HIPSfixed.rules'  # Çıkış dosyasının yolu
filter_alert_lines(input_file, output_file)