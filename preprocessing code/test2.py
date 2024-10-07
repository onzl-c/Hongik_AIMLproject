import os
import csv
import random
import subprocess
import json
from collections import Counter
import math
import concurrent.futures
from datetime import datetime

# malicious = 0
malicious = 1

# 설정된 파일 경로
repo_dir = './DikeDataset/files/malware'
rules_path = '/home/onzl/capa/capa-rules'
output_csv = './onzl_final_dataset.csv'

# ATT&CK Tactic, MBC Behavior, Namespace 정의
att_tactics = [
    'Collection', 'Command and Control', 'Credential Access', 'Defense Evasion',
    'Discovery', 'Execution', 'Exfiltration', 'Impact', 'Impair Process Control',
    'Inhibit Response Function', 'Initial Access', 'Lateral Movement', 'Persistence', 
    'Privilege Escalation'
]
malware_behavior = [
    'Anti-Behavioral Analysis', 'Anti-Static Analysis', 'Collection', 'Command and Control', 
    'Communication', 'Cryptography', 'Data', 'Defense Evasion', 'Discovery', 'Excution', 'File System', 
    'Hardware', 'Impact', 'Memory', 'Operating System', 'Persistence', 'Process'
]
namespaces = [
    'anti-analysis', 'collection', 'communication', 'compiler',
    'data-manipulation', 'doc', 'executable', 'host-interaction',
    'impact', 'internal/limitation/file', 'lib', 'linking', 'load-code',
    'malware-family/plugx', 'nursery', 'persistence', 'runtime/dotnet', 'targeting'
]

# 엔트로피 계산 함수
def calculate_entropy_for_data(data):
    if not data:
        return 0
    byte_counts = Counter(data)
    data_len = len(data)
    entropy = 0
    for count in byte_counts.values():
        p_x = count / data_len
        entropy += -p_x * math.log2(p_x)
    return entropy

# 파일 크기 관련 피처를 추가하는 함수
def get_file_size_features(file_path):
    try:
        file_size = os.path.getsize(file_path)
        # 특정 임계값을 기준으로 파일 크기를 비율로 표현하거나 다른 형태로 변환
        size_kb = file_size / 1024  # KB 단위로 변환
        size_mb = file_size / (1024 * 1024)  # MB 단위로 변환
        size_large_threshold = 1 if file_size > 10 * (1024 * 1024) else 0  # 10MB 이상의 파일 여부
        return file_size, size_kb, size_mb, size_large_threshold
    except:
        return 0, 0, 0, 0

# 패킹 여부 감지
def check_packing(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            if b'UPX' in data:
                return 1  # UPX 패킹된 파일
        return 0
    except:
        return 0

# 파일 타임스탬프 관련 피처
def get_file_timestamps(file_path):
    try:
        file_stats = os.stat(file_path)
        creation_time = datetime.fromtimestamp(file_stats.st_ctime)
        modification_time = datetime.fromtimestamp(file_stats.st_mtime)
        return creation_time, modification_time
    except:
        return None, None

# capa 명령어 실행 함수
def run_capa(binary_path, rules_path):
    try:
        capa_command = [
            "capa", binary_path, "-r", rules_path, "--signatures", rules_path, "-j"
        ]
        result = subprocess.run(capa_command, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running capa for {binary_path}: {result.stderr}")
            return None

        if not result.stdout.strip():
            print(f"No output from capa for {binary_path}")
            return None

        return json.loads(result.stdout)
    
    except Exception as e:
        print(f"Error: {e}")
        return None

# capa 결과에서 API 호출 정보를 추출
def extract_api_calls(capa_result):
    api_calls = []
    if "rules" in capa_result:
        for rule in capa_result["rules"].values():
            if "features" in rule:
                for feature in rule["features"]:
                    if feature["type"] == "api":
                        api_calls.append(feature["value"])
    return api_calls

# CSV에 파일 분석 결과 추가하는 함수
def analyze_file(binary_path, rules_path, writer):
    try:
        row = {}

        # 파일 크기 관련 피처
        file_size, size_kb, size_mb, size_large_threshold = get_file_size_features(binary_path)
        row['file_size'] = file_size
        row['size_kb'] = size_kb
        row['size_mb'] = size_mb
        row['size_large_threshold'] = size_large_threshold

        # 패킹 여부
        row['packed'] = check_packing(binary_path)

        # 파일 타임스탬프 피처
        creation_time, modification_time = get_file_timestamps(binary_path)
        row['creation_time'] = creation_time if creation_time else 'N/A'
        row['modification_time'] = modification_time if modification_time else 'N/A'

        # capa 명령 실행
        capa_result = run_capa(binary_path, rules_path)
        if capa_result:
            row['entropy'] = calculate_entropy_for_data(open(binary_path, 'rb').read())
            
            # API 호출 정보
            api_calls = extract_api_calls(capa_result)
            row['api_call_count'] = len(api_calls)
        
        # 악성 여부 (우리가 지정)
        row['malicious'] = malicious

        # CSV에 작성
        writer.writerow(row)

    except Exception as e:
        print(f"Error analyzing {binary_path}: {e}")

# 병렬 처리 실행 함수
def analyze_files_concurrently(files, rules_path, output_csv):
    with open(output_csv, mode='w', newline='') as file:
        csv_columns = ['file_name', 'entropy'] + \
                      [f'ATT_Tactic_{tactic}' for tactic in att_tactics] + \
                      [f'MBC_obj_{behavior}' for behavior in malware_behavior] + \
                      [f'namespace_{ns}' for ns in namespaces] + \
                      ['file_size', 'size_kb', 'size_mb', 'size_large_threshold', 'capabilityNum_matches'] + \
                      ['packed', 'creation_time', 'modification_time', 'api_call_count'] + \
                      ['malicious']
        
        writer = csv.DictWriter(file, fieldnames=csv_columns)
        writer.writeheader()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(analyze_file, f, rules_path, writer) for f in files]
            for future in concurrent.futures.as_completed(futures):
                future.result()

# 전체 파일을 분석하여 병렬 처리
def analyze_all_samples(repo_dir, rules_path, output_csv):
    all_files = []
    
    # 디렉토리에서 모든 파일을 수집
    for root, dirs, files in os.walk(repo_dir):
        for file_name in files:
            if file_name.endswith((".bin", ".exe", ".elf")):  # 바이너리, 실행 파일만 선택
                all_files.append(os.path.join(root, file_name))
    
    # 분석할 파일이 없는 경우 경고 메시지 출력
    if not all_files:
        print("No files found for analysis.")
        return

    # 병렬로 파일 분석 실행
    analyze_files_concurrently(all_files, rules_path, output_csv)

# 실행 부분
if __name__ == "__main__":
    repo_dir = './DikeDataset/files/malware'  # 파일이 저장된 디렉토리
    rules_path = '/home/onzl/capa/capa-rules'  # capa 규칙 파일 경로
    output_csv = './onzl_final_dataset.csv'  # 결과를 저장할 CSV 파일 경로

    # 전체 파일을 분석
    analyze_all_samples(repo_dir, rules_path, output_csv)