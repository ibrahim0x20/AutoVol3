import argparse
import sys
import hashlib
import os
import subprocess
import csv
import re


def calculate_sha256(file_path):
    print("Calculating the memory dump file hash ...")
    with open(file_path, 'rb') as f:
        hasher = hashlib.sha256()
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def delete_files_in_directory(project_path):
    # List all files in the directory
    files = os.listdir(project_path)

    # Iterate over each file and delete it
    for file_name in files:
        file_path = os.path.join(project_path, file_name)
        if os.path.isfile(file_path):
            os.remove(file_path)
            print(f"Deleted file: {file_path}")


def netscan2csv(data, output_file):
    
    netscan = []


    #offset = re.match(r'(\S+)\s+(\S+)\s+([\d\.:]+:\d+)\s+([\d\.\*:]+:[\*\d]+)\s+',lines[1])
    # print(offset, offset.span()[1])
    # exit()
    for line in data.split('\n')[1:]:
        #print('From output: ',line)
        

        if len(line) < 2:
            break
        row = []

        # Match on Offset(P)
        match = re.match(r'(\S+)\s+', line)
        span = match.span()[1]
        row.append(match[1])
    
        # Match on Protocol
        match = re.match(r'(\S+)\s+', line[span:])
        span += match.span()[1]


        #row = row + ',' + match[1]
        row.append(match[1])

        # Match on Local Addresses
        match = re.match(r'([\d\.:]+:\d+)\s+', line[span:])
        span += match.span()[1]


        # row = row + ',' + match[1]
        row.append(match[1])

        # Match on Foreign Address
        match = re.match(r'([\d\.\*:]+:[\*\d]+)\s+', line[span:])
        span += match.span()[1]
        # row = row + ',' + match[1]
        row.append(match[1])


        # Match on Status of connection
        match = re.match(r'(\S+)\s+', line[span:])

        # Special case to match on Processes PID if Status is empty string
        pid = ''
        if match[1].isdigit():
            # row = row + ',' + ''
            row.append('')
            # row = row + ',' + match[1]
            row.append(match[1])
            pid = match[1]
        else:
            # row = row + ',' + match[1]
            row.append(match[1])
        span += match.span()[1]

        # Match on Processes PID
        if not pid:
            match = re.match(r'([-\d]+)\s+', line[span:])
            if match:

                # row = row + ',' + match[1]
                row.append(match[1])
                pid = match[1]
            else:
                # row = row + ',' + ''
                row.append('')
            span += match.span()[1]
        if pid == '-1':
            row.append('')
            row.append('')
            netscan.append(row)
            continue

        match = re.match(r'(\S+)\s+', line[span:])
        span += match.span()[1]

        # row = row + ',' + match[1]
        row.append(match[1])

        if '?' in match[1]:
            row.append('')
            netscan.append(row)
            continue

        match = re.match(r'(.+)', line[span:])
        span += match.span()[1]


        # row = row + ',' + match[1]
        row.append(match[1])

        # if pid not in netscan:
        #     netscan[pid] = []
        #print('From netscan2csv: ','\t'.join(row))
        netscan.append(row)
    #print(netscan)
    # Regular expression pattern to match columns
    
    # Write the data to a CSV file
    with open(output_file, 'w', newline='') as csvfile:
        header=['Offset(P)', 'Proto', 'Local Address', 'Foreign Address', 'State', 'Pid', 'Owner', 'Created']
        writer = csv.writer(csvfile)
        
        writer.writerow(header)
        writer.writerows(netscan)

def run_plugin(memory_image_file, output_file, plugin):

    # Generate the required files for processing such as pslist, psscan, netscan ...
    # Required two argemnt: memory dump file and project directory
    # Should work on both windows and Linux


    # Run volatility plugin from python
    # if output_file == 'netscan.csv':
    #     command = ["vol2.py", "--profile", "Win10x64_15063", "-f", memory_image_file, output_file[:-4]]


    # else:
    # command = ["vol", "-r", "csv", "-f", memory_image_file, 'windows.'+output_file.split('/')[1][:-4]]

    # This creation of plugin causing problem when specifying path outside of the Autovlo3 folder --> Comment it and use argument from function
    #plugin = 'windows.'+output_file.split('/')[1][:-4]
    
    # Netscan plugin in volatility3 does not show process PID as volatility2 do
    # if plugin not in 'netscan':
    #     return
    if plugin == 'netscan':
        command = ["vol2.py", '--profile=Win10x64_15063', "-f", memory_image_file, plugin]

    else:
        command = ["vol", "-r", "csv", "-f", memory_image_file, 'windows.'+plugin]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        # Save the result to the specified CSV file
        # The csv file should be saved to project directory

        if plugin == 'netscan':
            netscan2csv(output, output_file)
        else:
            with open(output_file, 'w', encoding='utf-8') as csv_file:
                csv_file.write(output)
            
    except subprocess.CalledProcessError as e:
        print("Error:", e)
        print("Return Code:", e.returncode)
        print("Command Output:", e.output)
    except Exception as e:
        print("An error occurred in run_plugin:", str(e))

def csvgen(memory_image_file, project_path):

    csv_files = ['pslist.csv', 'psscan.csv', 'pstree.csv', 'dlllist.csv', 'cmdline.csv', 'netstat.csv', 'netscan.csv', 'handles.csv', 'getsids.csv']
    
    try:
        
        # Use the os.listdir() function to get a list of files in the directory
        files = os.listdir(project_path)

        for file in csv_files:
            
            if file not in files:
                print('File not found:', file)
                print('Generate file:', file,'...')
                output_file = os.path.join(project_path, file)
                
                run_plugin(memory_image_file,output_file, file[:-4])
                
                # if file == 'dlllist.csv':
                #     result = list_dlls(img_files[0])
                # elif file == 'cmdline.csv':               
    
    except FileNotFoundError:
        print(f"The directory '{memory_image_file}' does not exist.")
    except PermissionError:
        print(f"You do not have permission to access '{memory_image_file}'.")
    except Exception as e:
        print(f"An error occurred in csvgen: {str(e)}")

                   
def baseline(project_path, baseline_file):



    try:
        output_file = os.path.join(project_path, 'anomaly_baseline.txt')

        
        
        # Define the command as a list of strings
        command = ["python3", "/opt/memory-baseliner/baseline.py", "-proc", '--cmdline', "-i", "memory/base-rd01-memory.img", 
        "--loadbaseline", '--jsonbaseline', baseline_file, '-o', output_file] 
        # Run the command and capture its output
        #completed_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        completed_process = subprocess.run(command, capture_output=True, check=True, text=True)

        output = completed_process.stderr
        # You should save the outpu to debug errors and find if baseline not working correctly
        
        print(output)
    except subprocess.CalledProcessError as e:
        
        print("Error:", e)
        print("Return Code:", e.returncode)
        print("Command Output:", e.stderr)
    except Exception as e:
        print("An error occurred in baseline:", str(e))


    # print("Replacement complete. Output written to", 'suspecious_proc.txt')


def main():

    # Verify the memory dump file if it is valid or not
    # Find the operating system profile in the memory image
    # "--profile=Win10x64_15063
    # Save the initialization files to the project folder provided as an argument to autovol3.py
    # If the required files exist, don't run this script
    # If the project folder is not exist, create one



    # Verify the memory dump file if it is valid or not
    # The goal of this part of the code is to fail fast before doing any processing. The easiest plugin to use is image info, windows.info
    # What if it is a Linux image or any other operating system image?
    # command = ["vol2.py", '--profile=Win10x64_16299', "-f", args.f, 'netscan']


    command = ["vol", "-f", args.f, 'windows.info']

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout

        print(output)
            
    except subprocess.CalledProcessError as e:
        print("Error:", e)
        print("Return Code:", e.returncode)

        if "A translation layer requirement was not fulfilled" in e.output:
            print(f"The image file provided '{args.f}' is not valid")
            debug_msg = """Please Verify that:
        A file was provided to create this layer (by -f, --single-location or by config)
        The file exists and is readable
        The file is a valid memory image and was acquired cleanly
        """
            print(debug_msg)
            sys.exit(0)
    except Exception as e:
        print("An error occurred in run_plugin:", str(e))

    image_hash = calculate_sha256(args.f)
    image_signature_path = os.path.join(args.p, 'image_signature')

    if not os.path.isdir(args.p):
        os.makedirs(args.p)
        print(f"Project folder '{args.p}' created.")

        with open(image_signature_path, 'w') as signature_file:
            signature_file.write(image_hash)
        print("Image signature written to image_signature.")

    else:
        print(f"Project folder '{args.p}' already exists.")

        if os.path.exists(image_signature_path):
            with open(image_signature_path, 'r') as signature_file:
                old_image_hash = signature_file.read().strip()

            if image_hash == old_image_hash:
                print("This image has been analyzed before.")
            else:
                # Ask user if he want to work in the old project directory with new memory dump file or not
                response = input("This is a new image. Do you want to continue with new image or with the old one. If you continue with the new memory image file, all files generated during previous analysis will be deleted! [Y|n]: ")

                if response == 'Y' or response == 'y':
                    delete_files_in_directory(args.p)
                else:
                    sys.exit(0)

        else:
            print("Writing image signature to image_signature.")
            with open(image_signature_path, 'w') as signature_file:
                signature_file.write(image_hash)

    csvgen(args.f, args.p)

    # Check for anaomaly_baseline.csv. If it is not exist, create one
    # All the analysis depends on baseline json file from the Golden memory dump. If it is not provided from the 
    # command line, prompt the user to enter one.

     # Use the os.listdir() function to get a list of files in the directory
    files = os.listdir(args.p)
    if 'anomaly_baseline.txt' not in files:
        print("Creating 'anomaly_baseline.txt file...")

        if not args.b:
            args.b = input("Enter the json baseline file: ")

        baseline(args.p, args.b)

    # Check and Update the 'Malware Bazzaar' database. Update only one time per day, or the first time when you start the project
    # Prompt user for Yes|No
        
    # Check if the signed file exist: whitelist.csv generated by sigcheck.exe
        
    # Check and update RDS database one time per quarter
        
    # Add feeds and threat Intel for C2 and malicious IPs
        
    # Create a database for all files checked online from VirusTotal, HybridAnalysis, Any.Run, ...
        
    # Optinal: You can add option to print process tree

if __name__ == "__main__":

    # Argument parsing
    
    # Parse Arguments
    print('AutVol3 - Simple Memory Image Analyzer\n')
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', help='Memory image file', metavar='file')
    parser.add_argument('-p', help='Path to project directory', metavar='directory')
    parser.add_argument('-b', help='Baseline json file', metavar='file')

    parser.add_argument('--version', action='store_true', help='Shows welcome text and version of AutoVol3, then exit', default=False)

    # Add option for image profile if using vol2 or use vol3 windows.info and create the profile from the output
    # Add option for blacklist IPs                  ==> You don't need that, just the file balcklist.csv
    # Add option for choosing memory image file     --> Done
    # Add option to add VPN concentrator
    # Add option for project directory              --> Done
    # Add option to save previous projects in a folder and a list of hashes for memory image with image profile
    # Add option for MISP feed
    # Add option to the baseline.json Golden Image                                      ==> Done


    args = parser.parse_args()

    if not args.p or not args.f:
        print('Error: Both memory image file and project directory must be specified!\n')
        parser.print_help()
        sys.exit(1)

    # Show version
    if args.version:
        sys.exit(0)

    main()
 
    # autovol3 = AutoVol3(args)  # Uncomment this when AutoVol3 is defined
