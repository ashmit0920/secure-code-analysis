import os
import bandit
from bandit.core import config, manager

def run_bandit(file_path):
    # Initialize Bandit configuration
    b_conf = config.BanditConfig()
    b_mgr = manager.BanditManager(b_conf, 'file', None)

    # Run Bandit on the given file
    b_mgr.discover_files([file_path])
    b_mgr.run_tests()
    return b_mgr.results

def analyze_file(file_path):
    results = run_bandit(file_path)
    vulnerabilities = []

    for result in results:
        vuln_type = result.test_id
        line_number = result.lineno
        line = result.get_code(False).strip()
        vulnerabilities.append((vuln_type, line_number, line))

    return vulnerabilities

def analyze_directory(directory_path):
    all_vulnerabilities = {}
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                vulnerabilities = analyze_file(file_path)
                if vulnerabilities:
                    all_vulnerabilities[file_path] = vulnerabilities
    
    return all_vulnerabilities

def print_report(vulnerabilities):
    for file_path, issues in vulnerabilities.items():
        print(f"File: {file_path}")
        for vuln_type, line_number, line in issues:
            print(f"  {vuln_type} at line {line_number}: {line}")
        print()

if __name__ == "__main__":
    directory_path = input("Enter the directory path to analyze: ")
    vulnerabilities = analyze_directory(directory_path)
    print_report(vulnerabilities)
