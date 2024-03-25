import os
import subprocess
import re

directory_path = "./memory"

def baseline():
    try:
        # Use the os.listdir() function to get a list of files in the directory
        files = os.listdir(directory_path)
        
        
        
        # If proc_baseline.txt is not found, uncomment the next two lines to create it. It will takkke sometime. Be patient
        if 'proc_baseline.txt' not in files:
            # Define the command as a list of strings
            print('proc_baseline.txt file was found, generating this file ...')
            command = ["python3", "/opt/memory-baseliner/baseline.py", "-proc", "-i", "/cases/memory/base-rd01-memory.img", 
            "--loadbaseline", '--jsonbaseline', '/cases/precooked/memory/Win10x64_proc.json', '-o', directory_path+'/'+'proc_baseline.txt'] 
            # Run the command and capture its output
            completed_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


    except FileNotFoundError:
        print(f"The directory '{directory_path}' does not exist.")
    except PermissionError:
        print(f"You do not have permission to access '{directory_path}'.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


    # Read the content of the input file and replace '|' with ','
    with open(directory_path+'/'+'proc_baseline.txt', "r") as input_file:
        content = input_file.read()
        modified_content = content.replace("|", ",")
        for row in modified_content.strip().split('\n'):
            columns = row.split(',')
            if '.exe' in columns[6]:
                print(row)

    # Write the modified content back to the output file
    with open(directory_path+'/'+'suspecious_proc.txt', "w") as output_file:
        output_file.write(modified_content)

    print("Replacement complete. Output written to", 'suspecious_proc.txt')


