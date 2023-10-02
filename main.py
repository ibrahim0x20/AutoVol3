import csv
import os
import rogproc

commands = ['List the process DLLs', 'Lookup the process cmdline', 'Review the process communication', 'Print list of the process handles', 
            'Extract The ownership SID for each process']
csv_files = ['dlllist.csv', 'cmdline.csv', 'netscan.csv', 'handles.csv', 'getsids.csv']


rogproc.findrog()

print('The above processes are more likely the most suspecious processes. Select one of them by PID')
while True:
    print("Available Commands:")
    for index, command in enumerate(commands, start=1):
        print(f"{index}. {command}")
    print("0. Quit")

    try:
        choice = int(input("Enter the number corresponding to the command you want to select (or 0 to quit): "))

        if choice == 0:
            print("Exiting the program.")
            break
        elif 1 <= choice <= len(commands):
            selected_command = commands[choice - 1]
            corresponding_file = csv_files[choice - 1]
            print(f"Selected command: {selected_command}")
            print(f"Corresponding CSV file: {corresponding_file}")

            while True:
                # Prompt for the PID to search for
                pid_to_search = input("Enter the PID to search for (or type 'back' to go back to command selection): ")

                if pid_to_search.lower() == 'back':
                    break

                # Read and print the lines containing the specified PID from the selected CSV file
                file_path = os.path.join('./memory', corresponding_file)
                if os.path.exists(file_path):
                    with open(file_path, 'r', newline='') as csvfile:
                        csv_reader = csv.reader(csvfile)
                        header = next(csv_reader)  # Read the header
                        pid_index = None

                        # Find the index of 'PID' in the header
                        for index, column in enumerate(header):
                            if column == 'PID':
                                pid_index = index
                                break

                        if pid_index is not None:
                            # Print header
                            print(', '.join(header))

                            # Print rows with the specified PID
                            for row in csv_reader:
                                if len(row) > pid_index and row[pid_index] == pid_to_search:
                                    print(', '.join(row))
                        else:
                            print("PID column not found in the CSV file.")
                else:
                    print(f"File '{file_path}' not found.")
        else:
            print("Invalid choice. Please select a valid number.")
    except ValueError:
        print("Invalid input. Please enter a valid number.")
