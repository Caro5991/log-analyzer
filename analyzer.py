import re
import json
import os
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs.txt"
OUTPUT_FILE = "output.json"
THRESHOLD = 3

# Validar se arquivo de log existe
if not os.path.exists(LOG_FILE):
    print(f"[✗] Erro: Arquivo '{LOG_FILE}' não encontrado")
    exit(1)

ip_count = defaultdict(int)
ip_timestamps = defaultdict(list)

# Padrão regex melhorado
pattern = r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\]'

try:
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                timestamp = match.group(2)
                ip_count[ip] += 1
                ip_timestamps[ip].append(timestamp)
except IOError as e:
    print(f"[✗] Erro ao ler arquivo: {e}")
    exit(1)

suspicious = {}

for ip, count in ip_count.items():
    if count >= THRESHOLD:
        suspicious[ip] = {
            "attempts": count,
            "timestamps": ip_timestamps[ip]
        }

try:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(suspicious, f, indent=4)
except IOError as e:
    print(f"[✗] Erro ao escrever arquivo: {e}")
    exit(1)

print(f"[✔] Analysis complete. {len(suspicious)} suspicious IP(s) saved to {OUTPUT_FILE}")