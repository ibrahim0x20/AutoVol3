import csv

def read_blacklist_addresses(file_path):
    # Read the blacklist addresses from a file and return them as a set
    with open(file_path, mode='r') as blacklist_file:
        return set(line.strip() for line in blacklist_file)
        
def suspecious(csv_file_path, blacklist_file_path):
    print('Sixth modification')
    blacklist_addresses = read_blacklist_addresses(blacklist_file_path)
    # Open the CSV file and parse the data
    with open(csv_file_path, mode='r', newline='') as csv_file:
        csv_reader = csv.reader(csv_file)
        header = next(csv_reader)  # Read the header row
        filtered_processes = []

        # Define the browser processes you want to exclude
        browsers = ["chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe"]  # Add more if needed

        for row in csv_reader:
            local_addr = row[3].strip()
            local_port = row[4].strip()
            foreign_port = row[6].strip()
            foreign_addr = row[5].strip()
            owner = row[9].strip().lower()  # Convert owner to lowercase for case-insensitive comparison
            if foreign_port in ["80", "443", "8080"] and not any(browser in owner for browser in browsers):
                filtered_processes.append(row)
            elif any(browser in owner for browser in browsers) and foreign_port not in ["80", "443", "8080"]:
                filtered_processes.append(row)
            elif foreign_port == "3389" and not foreign_addr.startswith(("*", "::", "0.0.0.0", "127.0.0.1", "172.16.", "192.168.")):
                filtered_processes.append(row)
            elif foreign_addr in blacklist_addresses:
                filtered_processes.append(row)
            if (foreign_port == "3389") and \
               ((local_addr.startswith("172.16.") and foreign_addr.startswith("172.16.")) or \
                    (local_addr.startswith("192.168.") and foreign_addr.startswith("192.168."))):
                filtered_processes.append(row)
            if foreign_port in ["5985", "5986"] and not foreign_addr.startswith(("0.0.0.0", "127.0.0.1")):
                filtered_processes.append(row)

    return filtered_processes

