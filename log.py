import re
from collections import defaultdict
import csv
from typing import List, Dict, Tuple, Optional

def parse_log_file(log_file_path: str) -> List[Dict[str, str]]:
    log_entries = []
    log_entry_pattern = r'^(\S+) .* \[.*\] "(\S+) (/\S*) HTTP/\d\.\d" (\d{3}) \d*'

    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
            for line_num, line in enumerate(lines, 1):
                entry_match = re.match(log_entry_pattern, line)
                if entry_match:
                    ip_address = entry_match.group(1)
                    method = entry_match.group(2)
                    endpoint = entry_match.group(3)
                    status_code = entry_match.group(4)

                    log_entries.append({
                        'ip_address': ip_address,
                        'method': method,
                        'endpoint': endpoint,
                        'status_code': status_code
                    })
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
    except Exception as e:
        print(f"Unexpected error parsing log file: {e}")

    return log_entries

def count_requests_per_ip(log_entries: List[Dict[str, str]]) -> Dict[str, int]:
    ip_request_counts = defaultdict(int)
    for entry in log_entries:
        ip_request_counts[entry['ip_address']] += 1
    return dict(sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True))

def find_most_accessed_endpoint(log_entries: List[Dict[str, str]]) -> Optional[Tuple[str, int]]:
    endpoint_counts = defaultdict(int)
    for entry in log_entries:
        if entry['status_code'] == '200':
            endpoint_counts[entry['endpoint']] += 1
    if not endpoint_counts:
        return ("/", 0)
    return max(endpoint_counts.items(), key=lambda x: x[1])

def detect_suspicious_activity(log_entries: List[Dict[str, str]], threshold: int = 10) -> Dict[str, int]:
    failed_login_counts = defaultdict(int)
    for entry in log_entries:
        if entry['status_code'] == '401' and '/login' in entry['endpoint']:
            failed_login_counts[entry['ip_address']] += 1
    return {ip: count for ip, count in failed_login_counts.items() if count >= threshold}

def save_results_to_csv(
    ip_requests: Dict[str, int],
    most_accessed_endpoint: Tuple[str, int],
    suspicious_activity: Dict[str, int],
    output_file: str = 'log_analysis_results.csv'
):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    log_file_path = 'sample.log'
    log_entries = parse_log_file(log_file_path)

    if not log_entries:
        print("No log entries were parsed. Please check the log file and parsing logic.")
        return

    ip_requests = count_requests_per_ip(log_entries)
    most_accessed_endpoint = find_most_accessed_endpoint(log_entries)
    suspicious_activity = detect_suspicious_activity(log_entries)

    print("\nRequests per IP Address:")
    for ip, count in ip_requests.items():
        print(f"{ip:<15} {count:>5}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count:>5}")
    else:
        print("No suspicious activity detected.")

    save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity)
    print("\nResults saved to log_analysis_results.csv.")

if __name__ == "__main__":
    main()
