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
from datetime import datetime
from collections import defaultdict

# Define a function to parse the log
def parse_log(file_path):
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

    log_data = []
    for line in logs:
        # Skip lines that do not contain log entries
        if not re.match(r'^\d{4}-\d{2}-\d{2}', line):
            continue

        # Extract date and time
        date_time_str = line[:19]
        date_time = datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S')

        # Extract log level and message
        log_level = re.search(r'<(\d+)>', line).group(1)
        message = line[line.index(']') + 2:].strip()

        log_data.append({
            'datetime': date_time,
            'level': int(log_level),
            'message': message
        })

    return log_data

# Analyze the logs for specific information
def analyze_logs(log_data):
    client_connections = defaultdict(int)
    unique_clients = set()
    auth_success = 0
    disassociations = 0
    error_counts = defaultdict(int)

    for entry in log_data:
        message = entry['message']
        log_level = entry['level']

        # Count successful authentications
        if 'IEEE 802.1X succeeded to authorize' in message:
            auth_success += 1

        # Count disassociations
        if 'IEEE 802.11 disassociated' in message:
            disassociations += 1

        # Track IP addresses assigned to clients
        ip_match = re.search(r'send ack ip (\d+\.\d+\.\d+\.\d+)', message)
        if ip_match:
            client_connections[ip_match.group(1)] += 1

        # Track unique clients by MAC address
        mac_match = re.search(r'STA ([\da-f:]{17})', message)
        if mac_match:
            unique_clients.add(mac_match.group(1))

        # Count errors based on log level
        if log_level >= 3:  # Assuming level 3 and above are error levels
            error_counts[message] += 1

    return {
        'total_auth_success': auth_success,
        'total_disassociations': disassociations,
        'client_ip_counts': dict(client_connections),
        'unique_clients': len(unique_clients),
        'error_counts': dict(error_counts),
    }

# Export results to a text file
def export_results(results, output_file):
    with open(output_file, 'w') as file:
        file.write("Log Analysis Results\n")
        file.write("=====================\n")
        file.write(f"Total Successful Authentications: {results['total_auth_success']}\n")
        file.write(f"Total Disassociations: {results['total_disassociations']}\n")
        file.write(f"Unique Clients: {results['unique_clients']}\n")
        file.write("Client IP Address Counts:\n")
        for ip, count in results['client_ip_counts'].items():
            file.write(f"{ip}: {count} times\n")
        file.write("Error Counts:\n")
        for error_msg, count in results['error_counts'].items():
            file.write(f"{error_msg}: {count} times\n")

# Main function to run the analysis
def main():
    log_file_path = r'C:\Users\Computer\Desktop\New folder\syslog-2023-11-04.log.txt'  # Update this path

    log_data = parse_log(log_file_path)
    
    if not log_data:  # If no data was returned, exit early
        return

    analysis_results = analyze_logs(log_data)

    # Print the analysis results
    print(f"Total Successful Authentications: {analysis_results['total_auth_success']}")
    print(f"Total Disassociations: {analysis_results['total_disassociations']}")
    print(f"Unique Clients: {analysis_results['unique_clients']}")
    print("Client IP Address Counts:")
    for ip, count in analysis_results['client_ip_counts'].items():
        print(f"{ip}: {count} times")
    
    print("Error Counts:")
    for error_msg, count in analysis_results['error_counts'].items():
        print(f"{error_msg}: {count} times")

    # Export results to file
    output_file = r'C:\Users\Computer\Desktop\New folder\log_analysis_results.txt'
    export_results(analysis_results, output_file)
    print(f"Results exported to {output_file}")

if __name__ == "__main__":
    main()
