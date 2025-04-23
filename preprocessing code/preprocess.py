import os
import csv
import subprocess
import json
import time
from collections import Counter
import math
import pandas as pd

# 설정된 경로
base_dir = "/home/bigdata/Desktop/dataset"
rules_path = os.path.join(base_dir, "capa/rules")
# yara_rules_path = os.path.join(base_dir, "yara/malware_rules.yar")
capa_script_path = os.path.join(base_dir, "capa/capa/main.py")

# 결과 저장 디렉토리 및 파일명
output_dir = os.path.join(base_dir, "output")
os.makedirs(output_dir, exist_ok=True)

att_tactics = [
    'Collection', 'Command and Control', 'Credential Access', 'Defense Evasion', 'Discovery',
    'Execution', 'Exfiltration', 'Impact', 'Impair Process Control', 'Inhibit Response Function',
    'Initial Access', 'Lateral Movement', 'Persistence', 'Privilege Escalation'
]

malware_behavior = [
    'Anti-Behavioral Analysis', 'Anti-Static Analysis', 'Collection', 'Command and Control',
    'Communication', 'Cryptography', 'Data', 'Defense Evasion', 'Discovery', 'Excution',
    'File System', 'Hardware', 'Impact', 'Memory', 'Operating System', 'Persistence', 'Process'
]

namespaces = [
    'anti-analysis', 'collection', 'communication', 'compiler', 'data-manipulation', 'doc', 'executable',
    'host-interaction', 'impact', 'internal', 'lib', 'linking', 'load-code', 'malware-family', 'nursery',
    'persistence', 'runtime', 'targeting'
]

top_apis = [
    'CreateFileW', 'ReadFile', 'WriteFile', 'GetProcAddress', 'LoadLibraryA', 'VirtualAlloc',
    'CreateProcessW', 'RegOpenKeyExW', 'InternetOpenA', 'WinExec'
]

# yara_columns = ['yara_match_count']
columns = [
    'filename', 'class', 'entropy', 'analysis_time_sec', 'capabilityNum_matches', 'matched_rule_count',
    'string_count', 'number_count', 'mnemonic_count', 'unique_api_calls'
] + [f'api_{api}' for api in top_apis] + \
    [f'ATT_Tactic_{t}' for t in att_tactics] + \
    [f'MBC_obj_{b}' for b in malware_behavior] + \
    [f'namespace_{ns}' for ns in namespaces] # + yara_columns

def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        if not data:
            return 0
        byte_counts = Counter(data)
        data_len = len(data)
        entropy = -sum((count / data_len) * math.log2(count / data_len) for count in byte_counts.values())
        return entropy

def run_capa(binary_path, rules_path, output_json_path, output_log_path):
    try:
        capa_command = [
            'python3', '-m', 'capa.main', binary_path,
            '-r', rules_path,
            '--signatures', rules_path,
            '-f', 'pe', '--json'
        ]
        print(f"[INFO] Running capa on file: {binary_path}")
        print(f"[INFO] CAPA command: {' '.join(capa_command)}")

        start = time.time()
        result = subprocess.run(capa_command, capture_output=True, text=True, timeout=60)
        elapsed = time.time() - start

        with open(output_log_path, 'w') as f:
            f.write(result.stdout + "\n" + result.stderr)

        if result.returncode != 0 or not result.stdout.strip():
            print(f"[!] CAPA 실행 실패 또는 출력 없음: {binary_path}")
            return None, elapsed

        with open(output_json_path, 'w') as f:
            f.write(result.stdout)

        return output_json_path, elapsed

    except Exception as e:
        print(f"[!] Error running capa: {e}")
        return None, 0
    
"""def run_yara(binary_path, yara_rules_path):
    try:
        yara_command = ["yara", "-r", yara_rules_path, binary_path]
        print(f"[INFO] Running YARA: {' '.join(yara_command)}")
        result = subprocess.run(yara_command, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            matches = result.stdout.strip().splitlines()
            print(f"[INFO] YARA matches found: {matches}")
            return matches
        else:
            print(f"[WARNING] No YARA match or error for {binary_path}. stderr: {result.stderr}")
        return []
    except Exception as e:
        print(f"[!] YARA error on {binary_path}: {e}")
        return []"""

def extract_api_features(rule):
    apis = []
    if 'features' in rule:
        for k, v in rule['features'].items():
            if k == 'api' and isinstance(v, list):
                apis.extend([item for item in v if isinstance(item, str)])
            elif isinstance(v, list):
                for sub in v:
                    if isinstance(sub, dict) and 'api' in sub:
                        apis.append(sub['api'])
    return apis

def analyze_with_capa(binary_path, rules_path):
    try:
        file_name = os.path.basename(binary_path)
        output_dir_n = os.path.join(output_dir, "temp")
        os.makedirs(output_dir_n, exist_ok=True)
        output_json_file = os.path.join(output_dir_n, f"{file_name}.json")
        output_log_file = os.path.join(output_dir_n, f"{file_name}.log")

        log_file_path, elapsed = run_capa(binary_path, rules_path, output_json_file, output_log_file)
        if not log_file_path or not os.path.exists(log_file_path):
            return None

        with open(log_file_path, 'r') as log_file:
            capa_result = json.load(log_file)

        entropy = calculate_entropy(binary_path)
        att_tactic_matches = {t: 0 for t in att_tactics}
        mbc_behavior_matches = {b: 0 for b in malware_behavior}
        namespace_matches = {ns: 0 for ns in namespaces}
        matched_rules = set()
        all_api_calls = []
        string_count = 0
        number_count = 0
        mnemonic_count = 0
        capability_num_matches = 0

        for rule_name, rule in capa_result.get('rules', {}).items():
            matched_rules.add(rule_name)
            meta = rule.get('meta', {})
            for attack in meta.get('attack', []):
                if attack.get('tactic') in att_tactic_matches:
                    att_tactic_matches[attack['tactic']] += 1
            for mbc in meta.get('mbc', []):
                if mbc.get('objective') in mbc_behavior_matches:
                    mbc_behavior_matches[mbc['objective']] += 1
            ns = meta.get('namespace', '').split('/')[0]
            if ns in namespace_matches:
                namespace_matches[ns] += 1

            features = rule.get('features', {})
            all_api_calls.extend([item for item in features.get('api', []) if isinstance(item, str)])
            string_count += len(features.get('string', []))
            number_count += len(features.get('number', []))
            mnemonic_count += len(features.get('mnemonic', []))
            capability_num_matches += len(rule.get('matches', []))

        # yara_matched = run_yara(binary_path, yara_rules_path)

        row = {
            'filename': file_name,
            'entropy': entropy,
            'analysis_time_sec': round(elapsed, 3),
            'capabilityNum_matches': capability_num_matches,
            'matched_rule_count': len(matched_rules),
            'string_count': string_count,
            'number_count': number_count,
            'mnemonic_count': mnemonic_count,
            'unique_api_calls': len(set(all_api_calls))
            # 'yara_match_count': len(yara_matched)
        }

        for api in top_apis:
            row[f'api_{api}'] = int(api in all_api_calls)
        for t in att_tactics:
            row[f'ATT_Tactic_{t}'] = att_tactic_matches[t]
        for b in malware_behavior:
            row[f'MBC_obj_{b}'] = mbc_behavior_matches[b]
        for ns in namespaces:
            row[f'namespace_{ns}'] = namespace_matches[ns]

        return row

    except Exception as e:
        print(f"Error analyzing {binary_path}: {e}")
        return None

def analyze_dir(dir_n):
    dir_path = os.path.join(base_dir, f"dir_{dir_n}")
    data_root = os.path.join(dir_path, "data")
    csv_root = os.path.join(dir_path, "csv")
    output_csv = os.path.join(output_dir, f"output_dir_{dir_n}.csv")

    if not os.path.isdir(data_root) or not os.path.isdir(csv_root):
        print(f"[ERROR] {dir_path}에 data 또는 csv 디렉토리가 없습니다.")
        return

    processed_files = set()
    if os.path.exists(output_csv):
        try:
            df_existing = pd.read_csv(output_csv, dtype=str)
            if 'filename' in df_existing.columns:
                processed_files = set(df_existing['filename'].dropna().astype(str).str.strip())
        except Exception as e:
            print(f"[WARNING] 기존 CSV 로드 중 오류: {e}").tolist())
        except Exception as e:
            print(f"[WARNING] 기존 CSV 로드 중 오류: {e}")

    else:
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()

    data_subdirs = sorted([d for d in os.listdir(data_root) if os.path.isdir(os.path.join(data_root, d))])
    csv_files = sorted([f for f in os.listdir(csv_root) if f.endswith(".csv")])

    for data_subdir, csv_file in zip(data_subdirs, csv_files):
        data_path = os.path.join(data_root, data_subdir)
        csv_path = os.path.join(csv_root, csv_file)

        df = pd.read_csv(csv_path, dtype=str)
        df.set_index("filename", inplace=True)

        data_files = [f for f in os.listdir(data_path) if f.endswith((".exe", ".bin", ".elf", ".vir"))]
        label_files = df.index.tolist()

        if set(data_files) != set(label_files):
            print(f"[WARNING] 파일 이름 불일치: {csv_path} <-> {data_path}, 건너뜁니다.")
            continue

        for file in data_files:
            if str(file) in processed_files:
                print(f"[SKIP] 이미 처리된 파일: {file}")
                continue

            file_path = os.path.join(data_path, file)
            row = analyze_with_capa(file_path, rules_path)
            if row:
                row['class'] = int(df.loc[file, 'class'])
                for col in columns:
                    row.setdefault(col, 0)
                with open(output_csv, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=columns)
                    writer.writerow(row)
                print(f"[✔] 처리 완료: {file}")
            else:
                print(f"[!] 분석 실패: {file}")

if __name__ == "__main__":
    analyze_dir(1) # put 1 to 4