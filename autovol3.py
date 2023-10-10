import subprocess
import os
import csv
import sys
from sys import platform as _platform
import traceback
import argparse
import re

# Platform
os_platform = ""

if _platform == "linux" or _platform == "linux2":
    os_platform = "linux"
elif _platform == "darwin":
    os_platform = "macos"
elif _platform == "win32":
    os_platform = "windows"

# Win32 Imports
if os_platform == "windows":
    try:
        import wmi
        import win32api
        from win32com.shell import shell
        import win32file
    except Exception as e:
        print("Linux System - deactivating process memory check ...")
        os_platform = "linux"  # crazy guess

if os_platform == "":
    print("Unable to determine platform - LOKI is lost.")
    sys.exit(1)

class Node:
    def __init__(self, pid, ppid, image_file_name):
        self.pid = pid
        self.ppid = ppid
        self.image_file_name = image_file_name
        self.children = []

class AutoVol3(object):

    normal_proc = {}
    suspect_proc = {}

    regex_patterns = []
    whitelist_paths = []
    normal_paths =[]
    normal_paths_x86 =[]        # The normal path for a process if x86
    normal_process_path = []    # The normal path for a process
    process_path = {}           # The path for the running process from dlllist
    normal_sids = {}



    suspecious_proc_sids = {}
    suspect_cmdlines = {}
    suspect_netscan = {}
    
    dll_stacking = {}

    process_tree = {}
    pslist = {}
    psscan ={}
    dlllist = {}
    cmdline = {}
    netscan ={}
    getsids ={}

    baseline_proc = {}
    evidence_bag = []

    score = {}

    plugins = ['pslist', 'psscan', 'pstree', 'dlllist', 'cmdline', 'netstat', 'netscan', 'handle', 'getsids']
    
    analyze = ['List suspecious processes from EPROCESS', 'List suspecious processes with memory scanning', 'List suspecious cmdlines', 'List suspecious DLLs', 
               'List suspecious communications from EPROCESS', 'List suspecious communications with memory scanning', 'Compare the suspect image with baseline', 
               'List processes running with suspecious account']
    
    csv_files = ['pslist.csv', 'psscan.csv', 'pstree.csv', 'dlllist.csv', 'cmdline.csv', 'netstat.csv', 'netscan.csv', 'handles.csv', 'getsids.csv']

    def __init__(self, image):

        self.image = image
        self.app_path = get_application_path()


        self.csvgen(os.path.join(self.app_path, args.p))
        self.initialize_normal_proc(os.path.join(self.app_path, 'normal_proc.txt'))
        self.initialize_normal_paths(os.path.join(self.app_path, 'normal_paths.txt'))
        self.initialize_normal_sids(os.path.join(self.app_path, 'normal_sids.txt'))
        self.initialize_whitelist_paths('whitelist.txt')
        self.initialize_regex_patterns('regex_patterns.txt')

        # Read the required file from running the volatility plugins.
        self.csv_reader('pslist.csv')
        self.csv_reader('psscan.csv')
        self.csv_reader('dlllist.csv')
        self.csv_reader('cmdline.csv')
        self.csv_reader('netscan.csv')
        self.csv_reader('getsids.csv')

        # Analyzing memory for suspicious processes
        self.procTree(os.path.join(self.app_path, args.p) + '/'+'pslist.csv')
        self.malproc(self.process_tree['4'])
        self.malpath()
        self.malcmdline()
        self.malcomm('blacklist.txt')
        self.baseline('proc_baseline.txt')
        self.malgetsids()
        self.find_processes_without_parents() 

        # The following function must be run the last one
        self.malicious_weight()
        
        
        header = ['Source Name', 'PID', 'PPID','Process Name', 'Path', 'Timestamps', 'Long Description']
        self.evidence_bag.append(','.join(header))

    def run_plugin(self, memory_image_path, output_file):

        # if output_file == 'netscan.csv':
        #     command = ["vol2.py", "--profile", "Win10x64_15063", "-f", memory_image_path, output_file[:-4]]

        # else:
        command = ["vol", "-r", "csv", "-f", memory_image_path, 'windows.'+output_file[:-4]]

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout
            # Save the result to the specified CSV file
            with open(os.path.join(self.app_path, args.p)+'/'+output_file, 'w', encoding='utf-8') as csv_file:
                csv_file.write(output)
                
        except subprocess.CalledProcessError as e:
            print("Error:", e)
            print("Return Code:", e.returncode)
            print("Command Output:", e.output)
        except Exception as e:
            print("An error occurred:", str(e))

    def csvgen(self, memory_image_path):

        # Specify the directory path you want to list files from
        #directory_path = "./memory"
        
        try:
            
            # Use the os.listdir() function to get a list of files in the directory
            files = os.listdir(memory_image_path)
            
            # Check if there are any .img files in the directory
            img_files = [file for file in files if file.endswith(".img")]
        
            if not img_files:
                print(f"No '.img' files found in '{memory_image_path}'.")
            else:
                # Loop through and print the names of .img fil

                for file in self.csv_files:
                    
                    if file not in files:
                        print('File not found:', file)
                        print('Generate file:', file,'...')
                        self.run_plugin(memory_image_path+'/'+img_files[0],file)
                        
                        # if file == 'dlllist.csv':
                        #     result = list_dlls(img_files[0])
                        # elif file == 'cmdline.csv':               
        
        except FileNotFoundError:
            print(f"The directory '{memory_image_path}' does not exist.")
        except PermissionError:
            print(f"You do not have permission to access '{memory_image_path}'.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")


    def baseline(self, baseline_file):
        try:
            # Use the os.listdir() function to get a list of files in the directory
            fpath = os.path.join(self.app_path, args.p)
            files = os.listdir(fpath)

            # If proc_baseline.txt is not found, uncomment the next two lines to create it. It will takkke sometime. Be patient
            if baseline_file not in files:
                # Define the command as a list of strings
                print('proc_baseline.txt file was found, generating this file ...')
                command = ["python3", "/opt/memory-baseliner/baseline.py", "-proc", "-i", "/cases/memory/base-rd01-memory.img", 
                "--loadbaseline", '--jsonbaseline', '/cases/precooked/memory/Win10x64_proc.json', '-o', fpath+'/'+'proc_baseline.txt'] 
                # Run the command and capture its output
                completed_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


        except FileNotFoundError:
            print(f"The directory '{fpath}' does not exist.")
        except PermissionError:
            print(f"You do not have permission to access '{fpath}'.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")


        # Read the content of the input file and replace '|' with ','
        with open(fpath+'/'+'proc_baseline.txt', "r") as input_file:
            content = input_file.read()
            modified_content = content.replace("|", ",")
            
            modified_content = modified_content.strip().split('\n')[1:]

            for row in modified_content:
                columns = row.split(',')
                pid = columns[0]
                
                if '.exe' in columns[6]:
                    # if pid not in self.baseline_proc:
                    #     self.baseline_proc[pid] = []
                    self.baseline_proc[pid.strip('"')] = [''.join(row)]
        #print(self.baseline_proc)
        # Write the modified content back to the output file
        # with open(fpath+'/'+'suspecious_proc.txt', "w") as output_file:
        #     output_file.write(modified_content)

        # print("Replacement complete. Output written to", 'suspecious_proc.txt')

    def initialize_normal_proc(self, normal_proc_file):

        # Open and read the "normal_proc.txt" file
        with open(normal_proc_file, 'r') as file:
            for line in file:
                # Split each line into parent and child using ':' as the separator
                parent, child = line.strip().split(':')
                
                # If the parent is not in the dictionary, add it with an empty list of children
                if parent not in self.normal_proc:
                    self.normal_proc[parent] = []
                
                # Append the child to the parent's list of children
                self.normal_proc[parent].append(child)

        # The resulting dictionary is parsed_normal_proc

    def initialize_whitelist_paths(self, whitelist_file):

        # Open and read the "normal_proc.txt" file
        # You need to change this list "normal_proc.txt", because it is not clean, missing a lot of system files and dlls.
        with open(whitelist_file, 'r') as file:
            for line in file:
                # Split each line into parent and child using ':' as the separator
               self.whitelist_paths.append(line.strip('\n').split(',')[0].lower())
               #print(self.whitelist_paths)

    def initialize_normal_sids(self, normal_sids_file):

        # Open and read the "normal_proc.txt" file
        with open(normal_sids_file, 'r') as file:
            for line in file:
                # Split each line into parent and child using ':' as the separator
                parent, child = line.strip().split(':')
                
                # If the parent is not in the dictionary, add it with an empty list of children
                if parent not in self.normal_sids:
                    self.normal_sids[parent] = []
                
                # Append the child to the parent's list of children
                self.normal_sids[parent].append(child)


    def initialize_normal_paths(self, fpath):
        try:

            with open(fpath, newline='') as file:
                
                for line in file:
                   # self.normal_process_path.append(line.strip('\n').split('\\')[-1])

                    if 'program files (x86)' in line:
                        self.normal_paths_x86.append(line.strip('\n'))
                    else:
                        self.normal_paths.append(line.strip('\n'))

        except FileNotFoundError:
            print(f"The directory '{fpath}' does not exist.")
        except PermissionError:
            print(f"You do not have permission to access '{fpath}'.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")


    def initialize_blacklist_addresses(self, file_path):
    # Read the blacklist addresses from a file and return them as a set
        with open(file_path, mode='r') as blacklist_file:
            return set(line.strip() for line in blacklist_file)
        
    def initialize_regex_patterns(self, regex_file):
        # Read regex patterns from the file
        
        with open(regex_file, 'r') as patterns_file:
            for line in patterns_file:
                if line.startswith('#') or not line:  
                    continue                        # Skip this line and move to the next one
        
                line = line.strip()  # Remove leading/trailing whitespace
                if line:
                    self.regex_patterns.append(line)

        #print(self.regex_patterns)
        
    def procTree(self, proc_file):
        try:

            with open(proc_file, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                    
                for row in reader:
                    pid = row['PID']
                    ppid = row['PPID']
                    image_file_name = row['ImageFileName']

                    # Create a new node if it doesn't exist
                    if pid not in self.process_tree:
                        self.process_tree[pid] = Node(pid, ppid, image_file_name)

                    # Create a new node for the parent (PPID) if it doesn't exist
                    if ppid not in self.process_tree:
                        self.process_tree[ppid] = Node(ppid, 0, '') 

                    # Update the image file name for the current node
                    self.process_tree[pid].image_file_name = image_file_name

                    # Add the current node as a child to its parent
                    add_child(self.process_tree[ppid], self.process_tree[pid])

        except FileNotFoundError:
            print(f"The directory '{proc_file}' does not exist.")
        except PermissionError:
            print(f"You do not have permission to access '{proc_file}'.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
    
    def get_parent(self, pid):
        if pid in self.process_tree:
            node = self.process_tree[pid]
            parent_pid = node.ppid
            if parent_pid in self.process_tree:
                return self.process_tree[parent_pid]
        return None

    def find_parent_recursive(self, child_pid):
        # Get the parent node for the given child_pid
        parent_node = self.get_parent(child_pid)

        # Check if a parent node was found
        if parent_node:
            
            if parent_node.pid not in self.score:
                #print(f"Parent PID: {parent_node.pid}, Image File Name: {parent_node.image_file_name}")

                # Because score keeps track of pid while evidence_bag not. In addition, let the score of the parent is equal to child
                self.score[parent_node.pid] = self.score[child_pid] 
                self.collect_evidence(parent_node.pid )
            # If the parent is not services.exe, recursively find its parent
            if parent_node.image_file_name != 'svchost.exe':
                self.find_parent_recursive(parent_node.pid)
        # else:
        #     print(f"No parent found for PID {child_pid}.")

    def malproc(self,node):

        # 1. Should find abnormal parent-child relationship                                                             ==> Done
        # 2. Should find zero parent processes                                                                          ==> Done
        # 3. Should find processes running from weired paths                                                            ==> Done
        # 4. Should hidden/Unlinked processes like processes found in psscan, but not in pslist                         ==> Done
        # 5. When does the process start?                                                                          ==>TBD
        # 6. Should find any process that impersonate known processes and trying to blind in with normal processes      ==> Done


        # 1. Should find abnormal parent-child relationship

        if not node:
            return #suspect_proc

        for child in node.children:
            if not(node.image_file_name in self.normal_proc and child.image_file_name in self.normal_proc[node.image_file_name]):
                # print(node.image_file_name, child.image_file_name)            
                self.suspect_proc[child.pid] =self.pslist[child.pid][2:] + ', Suspecious parent-child relationship'
                
            self.malproc(child)

        return #suspect_proc

    # 2. Should find zero parent processes

    def find_processes_without_parents(self):
        for pid, node in self.process_tree.items():

            if node.ppid not in self.process_tree:
                #root_processes.append(pid)
                if pid == '0':
                    continue
                # print(self.pslist[node.children[0].pid])
                self.suspect_proc[node.children[0].pid] =self.pslist[node.children[0].pid][2:]+ ', Has a zero root parent'

    # 3. Should find processes running from weired paths

    def malpath(self):
        for pid in self.pslist:
            # print(self.process_path)
            if pid in self.process_path:
                path = self.process_path[pid].lower()

                if not ((path in self.normal_paths) or (path in self.normal_paths_x86)):
                        self.suspect_proc[pid] = self.pslist[pid]

    def find_cmd_child(self, path):

        # Iterate through each row in the CSV file and find the pid of a process executed by cmd.exe
        for pid in self.cmdline:
            # print(pid)
            row = self.cmdline[pid]
            args = row[2]
            # print(args)
            
            # Find the match in the 'Args' column
            if (path in args) and ('cmd.exe' not in args):
                pid = row[0]
                return pid  # Return the PID if a match is found

        return None  # Return None if no match is found for the given path

        
    def malcmdline(self):
        for pid in self.cmdline:
            # print(pid)
            row = self.cmdline[pid]
            args = row[2]
            pid = row[0]
                # Find the match in the 'Args' column
            # match = re.search(regex_pattern, args)

            # Iterate through each regex pattern
            for regex_pattern in self.regex_patterns:
                match = re.search(regex_pattern, args)
                if match:
                    path_executed = match.group(0)

                    if pid not in self.suspect_cmdlines:
                        self.suspect_cmdlines[pid] = row
                    #matched_paths.append(path_executed)

                    # print(matched_paths)
                    # When cmd.exe executed, it will create a process. search for this process and add it to the list. 
                    # If not found in cmdline list, look for it in psscan list
                    # You should also create the same for powershell.exe, wscript.exe, wmiprvse.exe, rundll32.exe, dllhost.exe, ...

                    if 'cmd\.exe' in regex_pattern:
                        pid = self.find_cmd_child(path_executed)
                        if pid:
                            if pid not in self.suspect_cmdlines:
                            # print(f"Path executed: {path_executed}, PID: {pid}")
                                self.suspect_cmdlines[pid] = self.cmdline[pid]
                        else:
                            print(f"No match found for {path_executed}")
                    

    def malcomm(self, blacklist_file_path):

        # Add option for VPN concentrator

        blacklist_addresses = self.initialize_blacklist_addresses(blacklist_file_path)

        # Define the browser processes you want to exclude
        browsers = ["chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe"]  # Add more if needed

        for pid in self.netscan:

            suspect_comm = []
            if len(self.netscan[pid]) > 1:

                for item in self.netscan[pid]:
                    
                    if 'WinStore.App.e' in item:
                        continue
                    row = item.split(',')

                    if (':::0' in row[2]) or ('0.0.0.0:0' in row[2]) or ('::1:0' in row[2]) :
                        continue

                    else:
                        tmp_addr = row[2].split(':')
                        src_ip = tmp_addr[0]
                        local_port = tmp_addr[1]

                        tmp_addr = row[3].split(':')
                        dst_ip = tmp_addr[0]
                        foreign_port = tmp_addr[1]

                        owner = row[6].lower()  # Convert owner to lowercase for case-insensitive comparison

                         # 1. Any process communicating over port 80, 443, or 8080 that is not a browser
                        if foreign_port in ["80", "443", "8080"] and not any(browser in owner for browser in browsers):
                           suspect_comm.append(','.join(row) + ' A process that is not browser using port: '+foreign_port)
                        
                        # 2. Any browser process not communicating over port 80, 443, or 8080
                        elif any(browser in owner for browser in browsers) and foreign_port not in ["80", "443", "8080"]:
                           suspect_comm.append(','.join(row)+ ' A browser communicating over unusual port: '+ foreign_port)

                        # 3. RDP connections (port 3389), particularly if originating from odd IP addresses. External RDP
                        # connections are typically routed through a VPN concentrator. If the src_ip is not from a VPN concentrator, this is malicious
                        elif foreign_port == "3389" and not src_ip.startswith(("*", "::", "0.0.0.0", "127.0.0.1", "172.16.", "192.168.")):
                           suspect_comm.append(','.join(row)+' External IP communicating directly with RDP port')

                        # 4. Connections to unexplained internal or external IP addresses. 
                        # External resources like IP reputation services can also provide additional context.
                        elif dst_ip in blacklist_addresses:
                           suspect_comm.append(','.join(row))

                        # 7. Workstation to workstation connections. Workstations don’t typically RDP, map shares, or authenticate to other workstations. 
                        # The expected model is workstations communicate with servers. Workstation to workstation connections often uncover lateral movement. 
                        elif ((src_ip.startswith("172.16.") and dst_ip.startswith("172.16.")) or \
                                (src_ip.startswith("192.168.") and dst_ip.startswith("192.168."))):
                           suspect_comm.append(','.join(row)+' Workstation to workstation communication')
                        elif foreign_port in ["5985", "5986"] and not dst_ip.startswith(("0.0.0.0", "127.0.0.1")):
                           suspect_comm.append(','.join(row))
            
            else:
                row = self.netscan[pid][0].split(',')

                if (':::0' in row[2]) or ('0.0.0.0:0' in row[2]) or ('::1:0' in row[2]) :
                    continue

                else:
                    tmp_addr = row[2].split(':')
                    src_ip = tmp_addr[0]
                    local_port = tmp_addr[1]

                    tmp_addr = row[3].split(':')
                    dst_ip = tmp_addr[0]
                    foreign_port = tmp_addr[1]

                    owner = row[6].lower()  # Convert owner to lowercase for case-insensitive comparison
                       
                     # 1. Any process communicating over port 80, 443, or 8080 that is not a browser
                    if foreign_port in ["80", "443", "8080"] and not any(browser in owner for browser in browsers):
                        suspect_comm.append(','.join(row)+ ' A process that is not browser using port: '+foreign_port)
                    
                    # 2. Any browser process not communicating over port 80, 443, or 8080
                    elif any(browser in owner for browser in browsers) and foreign_port not in ["80", "443", "8080"]:
                        suspect_comm.append(','.join(row)+ ' A browser communicating over unusual port: '+ foreign_port)

                    # 3. RDP connections (port 3389), particularly if originating from odd IP addresses. External RDP
                    # connections are typically routed through a VPN concentrator. If the src_ip is not from a VPN concentrator, this is malicious
                    elif foreign_port == "3389" and not src_ip.startswith(("*", "::", "0.0.0.0", "127.0.0.1", "172.16.", "192.168.")):
                        suspect_comm.append(','.join(row)+' External IP communicating directly with RDP port')

                    # 4. Connections to unexplained internal or external IP addresses. 
                    # External resources like IP reputation services can also provide additional context.
                    elif dst_ip in blacklist_addresses:
                        suspect_comm.append(','.join(row))

                    # 7. Workstation to workstation connections. Workstations don’t typically RDP, map shares, or authenticate to other workstations. 
                    # The expected model is workstations communicate with servers. Workstation to workstation connections often uncover lateral movement. 
                    elif ((src_ip.startswith("172.16.") and dst_ip.startswith("172.16.")) or \
                            (src_ip.startswith("192.168.") and dst_ip.startswith("192.168."))):
                        suspect_comm.append(','.join(row)+' Workstation to workstation communication')
                    elif foreign_port in ["5985", "5986"] and not dst_ip.startswith(("0.0.0.0", "127.0.0.1")):
                        suspect_comm.append(','.join(row))

            if suspect_comm:
                if pid not in self.suspect_netscan:
                    self.suspect_netscan[pid] = []
                self.suspect_netscan[pid].append(','.join(suspect_comm))


    def malgetsids(self):

        # suspecious_proc_sids = []
        for pid in self.getsids:
            row = self.getsids[pid][0]
            row = row.split(',')
            process = row[2]
            sid = row[3]

            if sid not in self.normal_sids:
                if process in self.normal_sids.get(sid, []):
                    #print(','.join(row), ' --> Malicious Process: System process running with user account')  # Join the values of the row into a CSV formatted string
                    row.append(' --> Malicious Process: System process running with user account')
                    self.suspecious_proc_sids[pid] = ','.join(row)        
                else:
                    self.suspecious_proc_sids[pid] = ','.join(row) 
                    #print(','.join(row))  # Join the values of the row into a CSV formatted string
            else:
                # Check if the process is not in the list of normal processes for the SID
                if process not in self.normal_sids[sid]:
                    row.append('Malicious Process: Uknown process running with system account')
                    self.suspecious_proc_sids[pid] =','.join(row)


    def csv_reader(self, csv_file):    
    # Create an empty dictionary to store data with "PID" as the index

        # Read and process the CSV file
        filePath = os.path.join(self.app_path, args.p) + '/'+csv_file
        
        if csv_file == 'netscan.csv':

            try:
                with open(filePath, 'r', newline='') as file:
                    header = next(file).split()
                    header[2] = ' '.join(header[2:4])
                    header[3] = ' '.join(header[4:6])
                    header[4] = header[6]
                    header[5] = header[7]
                    header[6] = header[8]
                    header[7] = header[9]

                    header = header[0:8]
                    pid_index = header.index('Pid')
                    
                    for line in file:
                        row = line.split()
                        
                        if len(row) < 10:
                            row.insert(4, '')

                        row[7] = ' '.join(row[7:])
                        row = row[0:8]

                        if len(row) > pid_index:
                            pid = row[pid_index]
                            if pid not in self.netscan:
                                self.netscan[pid] = []
                        self.netscan[pid].append(','.join(row))   

            except FileNotFoundError:            
                print(f"File '{csv_file}' not found.")
        else:

            try:
                with open(filePath, 'r', newline='') as csvfile:
                    csvreader = csv.reader(csvfile)
                    header = next(csvreader)  # Read the header

                    # Find the index of the "PID" column
                    pid_index = header.index('PID')

                    path_index = 0
                    if csv_file == 'dlllist.csv':
                        path_index = header.index('Path')

                    if csv_file == 'pslist.csv':
                    # Store the row as a comma-separated string in the dictionary
                        for row in csvreader:
                            if len(row) > pid_index:
                                pid = row[pid_index]
                            self.pslist[pid] = ','.join(row)

                    elif csv_file == 'psscan.csv':
                        for row in csvreader:
                            if len(row) > pid_index:
                                pid = row[pid_index]
                            self.psscan[pid] = ','.join(row)

                    elif csv_file == 'cmdline.csv':
                        for row in csvreader:

                            if len(row) >= 2:
                                if 'process exited' in row[3]:
                                    continue
                                pid = row[pid_index]
                                self.cmdline[pid] = row[1:]

                    elif csv_file == 'dlllist.csv':
                        for row in csvreader:
                            if len(row) > pid_index:
                                pid = row[pid_index]
                                if pid not in self.dlllist:
                                    self.dlllist[pid] = []
                            self.dlllist[pid].append(','.join(row))

                            if len(row) > path_index:
                                path = row[path_index]

                                if '.exe' in path:       #Skipp process path
                                    self.process_path[pid] = path
                                    continue
                                if path not in self.dll_stacking:
                                    self.dll_stacking[path] = 0
                            self.dll_stacking[path] += 1
                        
                    elif csv_file == 'getsids.csv':
                        for row in csvreader:
                            if len(row) == 0:
                                break

                            if len(row) > pid_index:
                                pid = row[pid_index]
                                if pid not in self.getsids:
                                    self.getsids[pid] = []
                            self.getsids[pid].append(','.join(row))

            
            except FileNotFoundError:
                print(f"File '{csv_file}' not found.")

    def collect_evidence(self, pid):
        """This funtion collects artifacts from all memory objects. This how you can print it print(self.artifact_bag['4'][0]['pslist'])"""
        #print(self.artifact_bag['4'][0]['pslist'])
        #print("I will collect artifacts using this funtion!")
        #print('This is the blueprint for this bag: ioc_collection = [pid: {<plugin1>: <row from plugin csv file>}, {<plugin2>: <row from plugin2 csv file>'+'}]')
        #self.evidence_bag[4] = [{'pslist':'0,2876,868,WmiPrvSE.exe,0x8c88b14e7580,10,-,0,False,2018-08-30 13:52:26.000000 ,N/A,Disabled'}]

        # if pid not in self.evidence_bag:
        #     self.evidence_bag[pid] = []
        
        # Collect evidence from PsList

        # reason = 'High privilege account SID: '

        # if pid in self.getsids:

        #     if len(self.getsids[pid]) > 1:

        #         for item in self.getsids[pid]:

        #             if ('Everyone' in item) or ('Users' in item) or ('This Organization' in item):
        #                 continue
                    
                
        #             columns = item.split(',')

        #             if 'Local System' == columns[4]:
        #                 reason += ' '.join(columns[3:])


        #             # Don't forget to add the enrichment from malgetsids function.
        #             elif '544' in columns[3]:
        #                 reason += 'The process spawned from a user context with Administrator privileges: '+' '.join(columns[3:])


                    
        #             if pid in self.suspecious_proc_sids:
        #                 reason2 = self.suspecious_proc_sids[pid].split(',')
        #                 if len(reason2) == 6:
        #                     reason += reason2[5]
        ppid = ''
        if pid in self.pslist:
            
            #print(self.psscan[pid])
            # evidence = {'pslist': self.pslist[pid]}
            #self.evidence_bag[pid].append(evidence)
            row = []
            row.append('pslist')
            columns = self.pslist[pid].split(',')
            row.append(columns[1])

            ppid = columns[2]
            row.append(columns[2])
            row.append(columns[3])

            path = ''
            if pid in self.process_path:
                path = self.process_path[pid]


            # You need to change this list because it is not clean, missing a lot of system files and dlls.
            # if path in self.whitelist_paths and self.score[pid] < 40:
            #     return

            row.append(path)
            row.append(columns[9])        

            if pid in self.suspect_proc:  
                reason = self.suspect_proc[pid].split(',')[11]             
                row.append(reason)

            self.evidence_bag.append(','.join(row))
        # print(pid, ': ',self.evidence_bag)


        # Collect evidence from PsScan
        if (pid in self.psscan) and (pid not in self.pslist):
            #print(self.psscan[pid])
            # evidence = {'psscan': self.psscan[pid]}
            # self.evidence_bag[pid].append(evidence)

            row = []
            row.append('psscan')
            columns = self.psscan[pid].split(',')
            row.append(columns[1])
            row.append(columns[2])
            row.append(columns[3])

            path = ''
            if pid in self.process_path:
                path = self.process_path[pid]

            row.append(path)
            row.append(columns[9])        

            # 4. Should hidden/Unlinked processes like processes found in psscan, but not in pslist
            # Hidden processes: Also add more details such as number of threads, parent process, ....
            if row[1] not in self.pslist:               
                row.append('Hidden/Unlinked: The process found in psscan, but not in pslist')
            self.evidence_bag.append(','.join(row))

        # Collect evidence from DllList
        
        if pid in self.dlllist:
            
            if len(self.dlllist[pid]) > 1:

                for item in self.dlllist[pid]:
                    
                    row =[]
                    row.append('dlllist')
                    # evidence = {'dlllist': self.dlllist[pid]}
                    # self.evidence_bag[pid].append(evidence)
                
                    columns = item.split(',')

                    if '.exe' in columns[6]:
                        continue

                    # We can add option to use this filtering or not. If we want to find malicious dlls we can use filtering, but
                    # if we want o understand the malcious process capabilities, we ignore filtering becuase used libraries can tell
                    # you the malware can do

                    if columns[6].lower() in self.whitelist_paths:
                        continue

                    if self.dll_stacking[columns[6]] > 2:       # Only keep dlls with low frequency as malicious dlls always rare
                        continue

                    row.append(columns[1])
                    row.append(ppid)
                    row.append(columns[2])
                    row.append(columns[6])
                    row.append(columns[7])
                    row.append('Whitelist the clean DLLs')
                    self.evidence_bag.append(','.join(row))
            else:
                row =[]
                row.append('dlllist')
                # evidence = {'dlllist': self.dlllist[pid]}
                # self.evidence_bag[pid].append(evidence)
            
                columns = self.dlllist[pid].split(',')
                if self.dll_stacking[columns[6]] > 5:       # Only keep dlls with low frequency as malicious dlls always rare
                    return
                row.append(columns[1])
                row.append(ppid)
                row.append(columns[2])
                row.append(columns[6])
                row.append(columns[7])
                row.append('Whitelist the clean DLLs')
                self.evidence_bag.append(','.join(row))
        

        # Collect evidence from CmdLine
        if pid in self.cmdline:
            # evidence = {'cmdline': self.cmdline[pid]}
            # self.evidence_bag[pid].append(evidence)

            row =[]
            row.append('cmdline')       
            #columns = self.cmdline[pid].split(',')
            row.append(self.cmdline[pid][0])          # Add pid to the list
            row.append(ppid)
            row.append(self.cmdline[pid][1])                    # Add process name
        
            pattern = r'"?([C|c]:\\[a-zA-Z0-9%\\ \(\)\.]*\.[eE][xX][eE]|[%\\]SystemRoot[%\\][a-zA-Z0-9%\\]*\.exe)\b'            
            paths = re.findall(pattern, self.cmdline[pid][2])
        
            if paths:
                paths = paths[0].strip('"')
        
            row.append(path)
            row.append('')
            row.append(self.cmdline[pid][2].replace('"', ''))
            self.evidence_bag.append(','.join(row))


        if pid in self.netscan:

            if len(self.netscan[pid]) > 1:

                for item in self.netscan[pid]:
                    row =[]
                    row.append('netscan')
                    # evidence = {'dlllist': self.dlllist[pid]}
                    # self.evidence_bag[pid].append(evidence)
                
                    columns = item.split(',')
                    row.append(columns[5])
                    row.append(ppid)
                    row.append(columns[6])
                    row.append(columns[1]+' ' + ' --> '.join(columns[2:4])+' '+columns[4])
                    row.append(columns[7])
                    row.append('I Will add info later')
                    self.evidence_bag.append(','.join(row))
            else:
                # evidence = {'netscan': self.netscan[pid]}
                # self.evidence_bag[pid].append(evidence)

                row =[]
                row.append('netscan')
                # evidence = {'dlllist': self.dlllist[pid]}
                # self.evidence_bag[pid].append(evidence)

                columns = self.netscan[pid][0].split(',')
                row.append(columns[5])
                row.append(ppid)
                row.append(columns[6])
                row.append(columns[1]+' ' + ' --> '.join(columns[2:4])+' '+columns[4])
                row.append(columns[7])
                row.append('I Will add info later')
                
                self.evidence_bag.append(','.join(row))

        if pid in self.getsids:

            if len(self.getsids[pid]) > 1:

                local_system = False
                for item in self.getsids[pid]:

                    if any(keyword in item for keyword in ['Power', 'Logon Session', 'Authentication Authority Asserted Identity', 'PlugPlay', 'Users', 
                                                           'This Organization', 'Everyone', 'DcomLaunch', 'High Mandatory Level']):
                        continue
            
                    row =[]
                    row.append('getsids')
                    columns = item.split(',')

                    if columns[4] == '-':
                        continue
                    row.append(columns[1])
                    row.append(ppid)
                    row.append(columns[2])
                    row.append(columns[3])
                    row.append('')

                    # Don't forget to add the enrichment from malgetsids function.

                    reason = columns[4]
                    if '544' in columns[3]:
                        reason = 'The process spawned from a user context with high privileges account: ' + reason
                    
                    if pid in self.suspecious_proc_sids:
                        reason2 = self.suspecious_proc_sids[pid].split(',')
                        if len(reason2) == 6:
                            reason = reason2[5] +': '+ reason
                    
                    row.append(reason)
                    self.evidence_bag.append(','.join(row))

    def create_SuperMemoryParser(self):

        header = ['Source Name', 'PID', 'Process Name', 'Path', 'Timestamps', 'Long Description']

        with open('SuperMemoryParser.csv', 'w') as mparser:
            mparser.write('\n'.join(self.evidence_bag))

    def malicious_weight(self):

        if self.pslist:
            for pid in self.pslist:
                weight = 0
                if pid in self.suspect_proc:
                    # if pid =='9036':
                    #     print(f"Found {pid} in suspect_proc: {self.suspect_proc[pid]}")
                    weight += 10

                    if 'Has a zero root parent' in self.suspect_proc[pid]:
                        weight += 30
                        
                
                if pid in self.suspecious_proc_sids:
                    # if pid =='9036':
                    #     print(f"Found {pid} in suspecious_proc_sids: {self.suspecious_proc_sids[pid]}")
                    weight += 10
                    

                if pid in self.suspect_cmdlines:
                    # if '9036' in self.suspect_cmdlines[pid]:
                    #     print(f"Found {pid} in suspect_cmdlines: {self.suspect_cmdlines[pid]}")
                    weight += 10

                if pid in self.suspect_netscan:
                    # if pid =='9036':
                    #     print(f"Found {pid} in suspect_netscan: {self.suspect_netscan[pid]}")
                    weight += 10
                
                # print(self.baseline_proc['1096'])
                if pid in self.baseline_proc:
                    # if pid =='9036':
                    #     print(f"Found {pid} in baseline_proc: {self.baseline_proc[pid]}")
                    weight += 10

                if weight > 30:
                    self.score[pid] = weight
                

# Function to add a child node to a parent node
def add_child(parent, child):
    parent.children.append(child)

# Function to recursively print the tree with '*' depth

def print_process_tree(node, depth=0):

    #     # Print the node's information with depth represented by '*' characters
    #     print("*" * depth + ' '*(12-depth)+ f"{node.pid}, {node.ppid}, {node.image_file_name}")
    #     # Recursively print children

    if node:
            # Print the header only for the root node
        if depth == 0:
            print(f"{'':<12}{'PID':<12}{'PPID':<12}{'Image File Name'}")
        # Check if the node is not the root (0, 0)
        if node.pid != '0':
            # Print the node's information with depth represented by '*' characters
            print("*" * depth + ' ' * (12 - depth) + f"{node.pid:<12}{node.ppid:<12}{node.image_file_name}")
        # Recursively print children
        for child in node.children:
            print_process_tree(child, depth + 1)

def get_application_path():
    try:
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        if "~" in application_path and os_platform == "windows":
            # print "Trying to translate"
            # print application_path
            application_path = win32api.GetLongPathName(application_path)
        #if args.debug:
        #    logger.log("DEBUG", "Init", "Application Path: %s" % application_path)
        return application_path
    except Exception as e:
        print("Error while evaluation of application path")
        traceback.print_exc()
        if args.debug:
            sys.exit(1)

def main(memory):
    
    """
    Argument parsing function
    :return:
    """
    # for pid in memory.score:
    #     print(pid, ': ', memory.score[pid])
    
    # child_pid = '8260'  # Replace with the PID of the child you want to find the parent for
    # # parent_node = memory.get_parent(child_pid)

    # memory.find_parent_recursive(child_pid)
    # parent_node = memory.get_parent(child_pid)

    # while parent_node.image_file_name != 'svchost.exe':

    #     parent_node = memory.get_parent(child_pid)

    #     if parent_node:
    #         print(f"Parent PID: {parent_node.pid}, Image File Name: {parent_node.image_file_name}")
    #     else:
    #         print(f"No parent found for PID {child_pid}.")

    #     child_pid = parent_node.pid


    pid_list = [key for key in memory.score]

    for pid in pid_list:
        memory.collect_evidence(pid)
        #print(pid, ': ', memory.score[pid])
        # parent = memory.pslist[pid].split(',')[2]

        memory.find_parent_recursive(pid)

        # if parent not in memory.score:
        #     memory.collect_evidence(parent)
    
    memory.create_SuperMemoryParser()

    while True:

        print("Available plugins to explore memory data:")
        for index, command in enumerate(memory.plugins, start=1):
            print(f"{index}. {command}")
            
        print("0. Exit") 
        
        try:
            choice = int(input("Enter the plugin number you want to select (or 0 to quit): "))
            if choice > len(memory.plugins):
                print("\nInvalid input. Please enter a valid number.")
                continue
            if choice == 0:
                print(memory.score)
                break
            selected_command = memory.plugins[choice - 1]
            corresponding_file = memory.csv_files[choice - 1]
            print(f"Selected command: {selected_command}")
            print(f"Corresponding CSV file: {corresponding_file}")

            if selected_command == 'pslist':
                for pid in memory.pslist:
                    print(memory.pslist[pid])

            if selected_command == 'psscan':
                for pid in memory.psscan:
                    print(memory.psscan[pid])

            if selected_command == 'pstree':
                print_process_tree(memory.process_tree['0'])

            if selected_command == 'dlllist':
                for pid in memory.dlllist:
                    print(memory.dlllist[pid])

            if selected_command == 'cmdline':
                for pid in memory.cmdline:
                    print(memory.cmdline[pid])

            if selected_command == 'netscan':
                for pid in memory.netscan:
                    print(memory.netscan[pid])

            if selected_command == 'getsids':
                for pid in memory.getsids:
                    print(memory.getsids[pid])

            print("1. Display only suspecious processes")
            print("2. Continue with full list")
            print("0. Back") 

            try:
                choice = int(input("Select one option (or 0 go back): "))
                if choice == 0:
                    continue

                elif choice == 1:
                    while True:
                        print("Display only suspecious processes:")
                        for index, command in enumerate(memory.analyze, start=1):
                            print(f"{index}. {command}")
                        print("0. Back")                        

                        try:
                            choice = int(input("Enter the number corresponding to the analysis you want to select (or 0 go back): "))

                            if choice == 0:                            
                                break

                            elif choice <= len(memory.analyze):
                                if choice == 1:
                                    #suspect_proc = memory.malproc(memory.process_tree['4'])
                                    for pid in memory.suspect_proc:
                                        print(memory.suspect_proc[pid])
                                    print('\n\nThe above processes are more likely the most suspecious processes. Select one of them by PID\n\n')

                                elif choice == 3:
                                    for pid in memory.suspect_cmdlines:
                                        print(memory.suspect_cmdlines[pid])

                                elif choice == 5:
                                    print('\nThis function have not been implemted, please do it!')
                                    continue

                                    suspect_proc = memory.malcomm('blacklist.txt')
                                    print('\n'.join(suspect_proc))

                                elif choice == 6:
                                    for pid in memory.suspect_netscan:
                                        print(memory.suspect_netscan[pid])

                                elif choice == 7:
                                    for pid in memory.baseline_proc:
                                        print(memory.baseline_proc[pid].replace('"', ''))
                                    
                                elif choice == 8:
                                    memory.malgetsids()

                                    for pid in memory.suspecious_proc_sids:  
                                        print(memory.suspecious_proc_sids[pid])

                                while True:
                                    # Prompt for the PID to search for
                                    pid_to_search = input("\n\nEnter the suspecious process PID that you want to collect as evidence (or type 'back' to go back to plugins selection): ")

                                    if pid_to_search.lower() == 'back':
                                        break
                                    memory.collect_evidence(pid_to_search)
                                            #print(memory.pslist[pid_to_search])

                            else:
                                print("Invalid choice. Please select a valid number.")

                        except ValueError:
                            print("Invalid input. Please enter a valid number.")

                        
                elif choice == 2:
                    while True:
                        # Prompt for the PID to search for
                        pid_to_search = input("\n\nEnter the suspecious process PID that you want to collect as evidence (or type 'back' to go back to plugins selection): ")

                        if pid_to_search.lower() == 'back':
                            break
                        memory.collect_evidence(pid_to_search)
                                #print(memory.pslist[pid_to_search])                    
                        #print(memory.evidence_bag)
                else:
                    print("Invalid choice. Please select a valid number.")

            except ValueError:
                print("Invalid input. Please enter a valid number.")

            # for key, value in memory.evidence_bag.items():
            #     formatted_output = []
            #     for item in value:
            #         for entry_type, entry_data in item.items():
            #             if entry_type == 'dlllist':
            #                 formatted_output.append(f'{entry_type}:')
            #                 formatted_output.extend([f'    {line}' for line in entry_data])

            #             elif entry_type == 'netscan':
            #                 formatted_output.append(f'{entry_type}:')
            #                 formatted_output.extend([f'    {line}' for line in entry_data])
            #             else:
            #                 formatted_output.append(f'{entry_type}: {entry_data}')
            #     print("\n".join(formatted_output))  
            #     print('\n')

        except ValueError:
            print("Invalid input. Please enter a valid number.")

if __name__ == "__main__":

    # Argument parsing
    
    # Parse Arguments
    parser = argparse.ArgumentParser(description='AutVol3 - Simple Memoray Image Analyzer')
    parser.add_argument('-p', help='Path to memory image and csv files like pslist, netscan ...', metavar='path', default='')
    parser.add_argument('--version', action='store_true', help='Shows welcome text and version of AutoVol3, then exit', default=False)

    # Add option for baseline
    # Add option for image profile if using vol2
    # Add option for blacklist IPs
    # Add option for chosing memory image file
    # Add option to add VPN concentrator

    args = parser.parse_args()

    if not args.p:
        print('Must specify memory image path!')
        parser.print_help()
        sys.exit(1)
 

    autovol3 = AutoVol3(args)

    # Show version
    if args.version:
        sys.exit(0)
    #suspect_proc = autovol3.malcomm('blacklist.txt')
    #autovol3.malgetsids()
    main(autovol3)

    # print('This is the last push')
    

    