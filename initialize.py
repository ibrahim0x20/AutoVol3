import csv
import json
import re
import pandas as pd
import sys

class Node:
    def __init__(self, pid, ppid, image_file_name):
        self.pid = pid
        self.ppid = ppid
        self.image_file_name = image_file_name
        self.children = []

def csv_reader(csv_file):    
# Create an empty dictionary to store data with "PID" as the index

    # Read and process the CSV file
    try:
        with open(csv_file, 'r', newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            # header = next(csvreader)  # Read the header

            # if 'pstree' in csv_file:
            #     return header.index('PID'), header.index('PPID'), header.index('ImageFileName'),list(csvreader)

            return  list(csvreader)
        
    except FileNotFoundError:            
            print(f"File '{csv_file}' not found.")


def read_file(sids_file):

    try:
    # Open and read the "normal_proc.txt" file
        with open(sids_file, 'r') as file:
            return file.readlines()
    except FileNotFoundError:            
            print(f"File '{sids_file}' not found.")
    except PermissionError:
            print(f"You do not have permission to access '{sids_file}'.")
    except Exception as e:
            print(f"An error occurred: {str(e)}")
        
def read_pslist(csv_file):
    pslist = {}
    ps_list = csv_reader(csv_file)
    
    if ps_list is None:
        return  # Exit if there was an error reading the CSV file
    
    pid_index = ps_list[0].index('PID')
    
    #header = ps_list[0]  # Read the header

    # Find the index of the "PID" column
    #pid_index = header.index('PID')
    
    # Store the row as a comma-separated string in the dictionary
    for row in ps_list[1:]:
        if len(row) > pid_index:
            pid = row[pid_index]
        pslist[pid] = ','.join(row[1:])

    return pslist


def read_psscan(csv_file):
    psscan = {}
    psscan_list = csv_reader(csv_file)
    
    if psscan_list is None:
        return  # Exit if there was an error reading the CSV file
    
    pid_index = psscan_list[0].index('PID')

    #header = psscan_list[0]  # Read the header

    # Find the index of the "PID" column
    # pid_index = header.index('PID')
    
    # Store the row as a comma-separated string in the dictionary
    for row in psscan_list[1:]:
        if len(row) > pid_index:
            pid = row[pid_index]
        psscan[pid] = ','.join(row)
    return psscan
    
#******************************************************************************
#           Read pstree csv file
#******************************************************************************

# Function to add a child node to a parent node
def add_child(parent, child):
    parent.children.append(child)

def read_pstree(csv_file):
    
    #df = pd.read_csv(csv_file)

    pstree_list = csv_reader(csv_file)

    
    if pstree_list is None:
        return  # Exit if there was an error reading the CSV file
    
    pid_index = pstree_list[0].index('PID')
    ppid_index = pstree_list[0].index('PPID')
    ImageFileName_index = pstree_list[0].index('ImageFileName')

    pstree = {}
               
    for row in pstree_list[1:]:
        if len(row) > pid_index:
            pid = row[pid_index]
            ppid = row[ppid_index]
            image_file_name = row[ImageFileName_index]

            # Create a new node if it doesn't exist
            
            if pid not in pstree:
                pstree[pid] = Node(pid, ppid, image_file_name)

            # Create a new node for the parent (PPID) if it doesn't exist
            if ppid not in pstree:
                pstree[ppid] = Node(ppid, 0, '') 

            # Update the image file name for the current node
            pstree[pid].image_file_name = image_file_name

        # Add the current node as a child to its parent
        add_child(pstree[ppid], pstree[pid])
    return pstree


# Function to recursively print the tree with '*' depth

def print_process_tree(pstree):
    print(len(pstree))
    
    print(f"{'':<12}{'PID':<12}{'PPID':<12}{'Image File Name'}")
    for root_pid, root_node in pstree.items():
        #print("Root Node:", root_pid)
        print_tree(root_node)


def print_tree(node, depth=0):

    #     # Print the node's information with depth represented by '*' characters
    #     print("*" * depth + ' '*(12-depth)+ f"{node.pid}, {node.ppid}, {node.image_file_name}")
    #     # Recursively print children

    if node:
            # Print the header only for the root node
        
        # Check if the node is not the root (0, 0)
        # if node.pid != '0': ===> Please don't use this condition as it hides a some nodes, some parts of the tree
            # Print the node's information with depth represented by '*' characters
        print("*" * depth + ' ' * (12 - depth) + f"{node.pid:<12}{node.ppid:<12}{node.image_file_name}")
        # Recursively print children
        for child in node.children:
            print_tree(child, depth + 1)


#print_process_tree(4)

def read_cmdline(csv_file):

    cmdline = {}
    cmdline_list = csv_reader(csv_file)

    if cmdline_list is None:
        return  # Exit if there was an error reading the CSV file
    
    pid_index = cmdline_list[0].index('PID')

     
    for row in cmdline_list[1:]:

        if len(row) >= 2:
            if 'process exited' in row[3]:
                continue
            pid = row[pid_index]
            cmdline[pid] = row[1:]      # I did not use ','.join(row) because some cmdline have "," that cause challnges when processing cmdline list
    return cmdline


def read_dlllist(csv_file):
    dlllist = {}
    dll_stacking = {}       # How many times the dll used in processes
    process_path = {}       # To know if the process is running from abnormal location

    dll_list = csv_reader(csv_file)

    if dll_list is None:
        return  # Exit if there was an error reading the CSV file
    
    pid_index = dll_list[0].index('PID')

    
    path_index = 6
    for row in dll_list:

        if len(row) > pid_index:
            pid = row[pid_index]
            if pid not in dlllist:
                dlllist[pid] = []                   # Every process PID has more than one DLL. Keep all dlls for every process in the same pid index
            dlllist[pid].append(','.join(row[1:]))      # Remove the first element of the row as it is zero for all --> TreeDepth

        # # Create a list of dlls frequency, when low frequency may be suspecious
        
        if len(row) > path_index:
            path = row[path_index]

            # Create a list of file location for running processes
            if '.exe' in path:       #Skipp process path and don't add .exe files to stacking dlls
                process_path[pid] = path
                continue
            if path not in dll_stacking:
                dll_stacking[path] = 0
            dll_stacking[path] += 1

    return dlllist, dll_stacking, process_path

#******************************************************************************
#           Read getsids csv file
#******************************************************************************

def read_getsids(csv_file):

    getsids = {}
    sids_list = csv_reader(csv_file)

    if sids_list is None:
        return  # Exit if there was an error reading the CSV file    
    
    pid_index = sids_list[0].index('PID')

    for row in sids_list:

        # I don't know when this if statement here, but I have to keep it for now. May because to end reading file
        if len(row) == 0:
            break

        if len(row) > pid_index:
            pid = row[pid_index]
            if pid not in getsids:
                getsids[pid] = []
        getsids[pid].append(','.join(row[1:]))

    return getsids

#******************************************************************************
#           Read handles csv file
#*******************************************************************

def read_handles(csv_file):

    handles = {}
    handles_list = csv_reader(csv_file)

    if handles_list is None:
        return  # Exit if there was an error reading the CSV file    
        
    pid_index = handles_list[0].index('PID')

    filter = ['File', 'Key', 'Mutant']  # 

    for row in handles_list:
        #print(','.join(row))
        if  len(row) == 0:
            continue
        if row[5] not in filter or row[7] == '':
            continue

        if len(row) > pid_index:
            pid = row[pid_index]
            if pid not in handles:
                handles[pid] = []       # Every process PID has a lot of handles. Keep all handles for every process in the same pid 
        handles[pid].append(row[1:])
    return handles



def read_netscan(netscan_file):
    
    netscan = {}

    netscan_list = csv_reader(netscan_file)
    
    if netscan_list is None:
        return  # Exit if there was an error reading the CSV file
    
    pid_index = netscan_list[0].index('Pid')

    #header = psscan_list[0]  # Read the header

    # Find the index of the "PID" column
    # pid_index = header.index('PID')
    
    # Store the row as a comma-separated string in the dictionary
    for row in netscan_list[1:]:
        if len(row) > pid_index:
            pid = row[pid_index]

            if pid not in netscan:
                netscan[pid] = []
        netscan[pid].append(','.join(row))
    return netscan

#****************************************************************************
#                           spawning_process()
#****************************************************************************
# Use this function to find parent child relationship
# Generate a list for normal_proc_file from the Golden Image Dump

def normal_spawning(baseline_file):


    # Assuming your JSON data is stored in a file named "data.json"
    with open(baseline_file, 'r') as file:
        data = json.load(file)

    # Print the extracted data
    # Print details for the first element
        
    parent_child = {}
    pid_name = {}

    for item in data:
        process_name = item['process_name']
        ppid = item['ppid']
        pid = item['pid']

        # Initialize an empty list for child processes
        if ppid not in parent_child:
            parent_child[ppid] = []
            
        pid_name[pid] = process_name

        # Append the current process to its parent's list
        if process_name not in parent_child[ppid]:
            parent_child[ppid].append(process_name)
    
    new_dict = {pid_name.get(k, k): v for k, v in parent_child.items()}
    
    return new_dict



#******************************************************************************
#                   Initialize White list applications
#******************************************************************************

def path_id(file_path):
    # Convert the file path to lowercase
    file_path_lower = file_path.lower()
    
    # Generate a hash value using the hash() function
    hash_value = hash(file_path_lower)
    
    # Convert the hash value to a positive integer (to avoid negative hash values)
    positive_hash_value = hash_value & ((1 << 64) - 1)
    
    # Convert the hash value to a hexadecimal string
    hex_hash_value = format(positive_hash_value, '016x')  # Adjust the padding as needed
    
    return hex_hash_value



def whitelist(whitelist_file):

        # Open and read the "normal_proc.txt" file
        # You need to change this list "normal_proc.txt", because it is not clean, missing a lot of system files and dlls.
    
    whitelist_d= csv_reader(whitelist_file)
    whitelist = {}

    if whitelist is None:
        return  # Exit if there was an error reading the CSV file    
        

    # Why I came with hash value look up (path_id) --> fast search algorithm o(n) instead of O(n*m)
    
    for row in whitelist_d[1:]:
        id = path_id(row[0])
        whitelist[id] = row

    return  whitelist

#************************************************************************************************************
#************************************************************************************************************
class TreeNode:
    def __init__(self, data):
        self.data = data
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)


    def __repr__(self, level=0):
        ret = "*"
        if level > 0 :
            ret += "*" * level
            # print("*" * depth + ' ' * (12 - depth) + f"{node.pid:<12}{node.ppid:<12}{node.image_file_name}")
        ret += ' ' * (12 - level) + f"{self.data[0]:<12}{self.data[1]:<12}{self.data[2]}\n"
        for child in self.children:
            ret += child.__repr__(level + 1)
        return ret

def build_tree_from_data(data):
    # Create a dictionary to map PID to its corresponding TreeNode
    node_map = {}
    roots = []
    
    # Iterate through the data to build the tree
    for line in data:
        tree_depth, pid, ppid, image_file_name, *rest = line
        node_data = (pid, ppid, image_file_name)
        node = TreeNode(node_data)
        node_map[pid] = node
        
        # If the node has no parent (PPID = 0), it's a root node
        if ppid in node_map:
            parent_node = node_map[ppid]
            parent_node.add_child(node)
        else:
            # If the node does not have a parent in the tree, it's a root node
            roots.append(node)
    
    return roots


# Build the tree from the data

# Read data from pstree.csv
def new_read_pstree(csv_file):
    data = []
    pstree_list=csv_reader(csv_file)
    
    for row in pstree_list[1:]:
        data.append(tuple(row))

    root_nodes = build_tree_from_data(data)

    return root_nodes


# Example usage:
# csv_file = "memory/pstree.csv"
# root_nodes = new_read_pstree(csv_file)

# Print the tree
# for i, root_node in enumerate(root_nodes):
#     new_root = True if i > 0 else False
#     print(root_node.__repr__(new_root=new_root))

# for root_node in root_nodes:
#     print(root_node)


def normal_sids(normal_sids_file):

    lines = read_file(normal_sids_file)   
    normal_sids = {} 

    if lines:
        for line in lines:
                # Split each line into parent and child using ':' as the separator
            parent, child = line.strip().split(':')
    
                # If the parent is not in the dictionary, add it with an empty list of children
            if parent not in normal_sids:
                    normal_sids[parent] = []
                
                # Append the child to the parent's list of children
            normal_sids[parent].append(child)
    return normal_sids

#print(normal_sids("normal_sids.txt"))


def read_regex(regex_file):
    # Read regex patterns from the file

    lines = read_file(regex_file)   
    if lines is None:
        return
    
    regex_patterns = []
    
    
    for line in lines:
        if line.startswith('#') or not line:  
            continue                        # Skip this line and move to the next one

        line = line.strip()  # Remove leading/trailing whitespace
        if line:
            regex_patterns.append(line)
    return regex_patterns

#*****************************************************************************************************
#                           Black List Addresses
#*****************************************************************************************************

def read_blacklist(blacklist_addresses):
    # Read the blacklist addresses from a file and return them as a set where set prevent duplication

    lines = read_file(blacklist_addresses)   
    return set(line.strip() for line in lines)

def read_anomaly_baseline(anomaly_baseline_file):

    diff_proc_list = read_file(anomaly_baseline_file)

    if diff_proc_list is None:
        print(f"The '{anomaly_baseline_file}' has a problem!!")
        sys.exit(1)

    diff_proc = {}
    for proc in diff_proc_list[1:]:
        pid = proc.split('|')[0].strip('"')
        if pid not in diff_proc:
            diff_proc[pid] = []
        diff_proc[pid].append(proc)

    return diff_proc

# *********************************************************************
#                   Testing Area
#**********************************************************************
#normal_spawning('Win10x64_proc.json')


 