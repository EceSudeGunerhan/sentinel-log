import random

# Giriş ve çıkış dosyalarının yolları
input_file = "access.log"  # Orijinal log dosyası
output_file = "web_server_logs_sample.log"  # Çıktı dosyası

# Rastgelelik sabitleniyor
random.seed(42)

# Satırları oku
with open(input_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Eğer toplam satır 50.000'den azsa uyar
if len(lines) < 50000:
    print(f"Uyarı: Toplam satır sayısı ({len(lines)}) 50.000'den az.")

# 50.000 satırı rastgele seç
sampled_lines = random.sample(lines, min(50000, len(lines)))

# Yeni dosyaya yaz
with open(output_file, "w", encoding="utf-8") as f:
    f.writelines(sampled_lines)

print(f"Rastgele 50.000 satır '{output_file}' dosyasına yazıldı.")
