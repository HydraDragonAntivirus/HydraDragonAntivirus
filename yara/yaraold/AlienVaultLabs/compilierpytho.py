import yara

def compile_and_save_yara_rule(rule_path, compiled_rule_path):
    try:
        rules = yara.compile(rule_path)
        rules.save(compiled_rule_path)
        return True
    except yara.SyntaxError as e:
        print("Syntax error in YARA rule: %s" % e)
    except yara.Error as e:
        print("YARA error: %s" % e)
    return False

# Derlemek istediğiniz YARA dosyasının ve kaydedilecek derlenmiş kuralın yollarını belirtin
rule_path = "Air3.yar"
compiled_rule_path = "compiled_rule"

# YARA kuralını derle ve kaydet
success = compile_and_save_yara_rule(rule_path, compiled_rule_path)

if success:
    print("YARA rule compiled and saved successfully!")
else:
    print("Failed to compile and save YARA rule.")
