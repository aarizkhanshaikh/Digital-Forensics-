def extract_header_info(header_file):
    important_fields = [
        "Received-SPF", "Authentication-Results", "ARC-Authentication-Results",
        "DKIM-Signature", "DMARC-Filter", "From", "To", "Subject", "Date"
    ]

    try:
        with open(header_file, 'r') as file:
            headers = file.read()  # Read entire file content as a single string

        print("Extracted Email Header Information:\n")
        for field in important_fields:
            found = False
            for line in headers.splitlines():
                if line.startswith(field):
                    print(f"{field}: {line}")
                    found = True
                    break
            if not found:
                print(f"{field}: Not Found")
            print()

    except FileNotFoundError:
        print(f"File '{header_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the script
header_file = "email_header.txt"  # Replace with your email header file
extract_header_info(header_file)












import re
from collections import defaultdict
from datetime import datetime

# Function to parse router log file
def parse_log(file_path):
    log_data = []
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(r'(\S+ \d+ \d+:\d+:\d+) (\S+) (\S+): (.*)', line)
            if match:
                timestamp, device, log_type, message = match.groups()
                log_data.append({
                    'timestamp': datetime.strptime(timestamp, '%b %d %H:%M:%S'),
                    'device': device,
                    'log_type': log_type,
                    'message': message
                })
    return log_data

# Function to generate summary
def generate_summary(log_data):
    summary = defaultdict(lambda: defaultdict(int))
    ip_addresses = set()
    events = defaultdict(int)

    for entry in log_data:
        log_type = entry['log_type']
        message = entry['message']
        summary[entry['device']][log_type] += 1
        
        # Extract IP addresses (if any) from the message
        ip_matches = re.findall(r'[0-9]+(?:\.[0-9]+){3}', message)
        ip_addresses.update(ip_matches)
        
        # Track common events or errors
        events[message.split(':')[0]] += 1

    # Print summary
    print("Log Summary Report")
    print("------------------")
    for device, logs in summary.items():
        print(f"Device: {device}")
        for log_type, count in logs.items():
            print(f"  {log_type}: {count}")
    print("\nUnique IPs:", ", ".join(ip_addresses))
    print("\nTop Events/Errors:")
    for event, count in sorted(events.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {event}: {count} occurrences")

# Main function
if __name__ == "__main__":
    file_path = "router_logs.txt"  # Replace with your log file path
    log_data = parse_log(file_path)
    generate_summary(log_data)
