import re
import csv
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 10  # Configurable threshold for suspicious activity

# Step 1: Parse the log file
def parse_log_file(file_path):
    log_entries = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                log_entries.append(line.strip())
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return []
    return log_entries

# Step 2: Extract requests per IP address
def count_requests_per_ip(log_entries):
    ip_counts = defaultdict(int)
    for entry in log_entries:
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)", entry)
        if match:
            ip = match.group(1)
            ip_counts[ip] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

# Step 3: Identify the most frequently accessed endpoint
def most_frequent_endpoint(log_entries):
    endpoint_counts = defaultdict(int)
    for entry in log_entries:
        match = re.search(r'\"(?:GET|POST|PUT|DELETE|OPTIONS) (.*?) HTTP', entry)
        if match:
            endpoint = match.group(1)
            endpoint_counts[endpoint] += 1
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1], default=("N/A", 0))
    return most_accessed

# Step 4: Detect suspicious activity
def detect_suspicious_activity(log_entries):
    failed_logins = defaultdict(int)
    for entry in log_entries:
        if '401' in entry or 'Invalid credentials' in entry:
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", entry)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True)

# Step 5: Output results to terminal and CSV
def save_results_to_csv(ip_counts, most_accessed, suspicious_activities):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP counts
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write suspicious activities
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activities)

# Main function
def main():
    log_file_path = 'sample.log'  # Path to your log file
    log_entries = parse_log_file(log_file_path)
    if not log_entries:
        return

    # Count requests per IP
    ip_counts = count_requests_per_ip(log_entries)
    print("Requests per IP:")
    for ip, count in ip_counts:
        print(f"{ip:<20} {count}")

    # Most accessed endpoint
    most_accessed = most_frequent_endpoint(log_entries)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detect suspicious activity
    suspicious_activities = detect_suspicious_activity(log_entries)
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activities:
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_results_to_csv(ip_counts, most_accessed, suspicious_activities)
    print("\nResults saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    main()
