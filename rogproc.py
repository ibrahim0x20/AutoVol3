
import csv
import io


normal_proc = {
    "System":['smss.exe','MemCompression'], "smss.exe":['csrss.exe', 'winlogon.exe', 'smss.exe', 'wininit.exe'], 
    "wininit.exe": ['services.exe', 'lsass.exe','lsaiso.exe', 'fontdrvhost.ex'], 
    "services.exe":['svchost.exe',  'OfficeClickToR', 'mfevtps.exe', 'SearchIndexer.', 'spoolsv.exe', 'armsvc.exe', 'HipMgmt.exe', 
                    'masvc.exe', 'mfemms.exe', 'FireSvc.exe', 'VsTskMgr.exe', 'vmacthlp.exe', 'macmnsvc.exe', 'SecurityHealth', 
                    'VGAuthService.', 'vmtoolsd.exe', 'ManagementAgen', 'macompatsvc.ex', 'mcshield.exe', 'msdtc.exe', 'WmiApSrv.exe'],
    "userinit.exe":['explorer.exe'], "winlogon.exe": ['LogonUI.exe', 'dwm.exe', 'fontdrvhost.ex', 'userinit.exe'],
    "svchost.exe":['RuntimeBroker.', 'iexplore.exe', 'backgroundTask', 'sihost.exe', 'ctfmon.exe', 'HxTsr.exe', 'taskhostw.exe', 
                   'SkypeHost.exe', 'SearchUI.exe', 'ShellExperienc'],
    "explorer.exe" : ['MSASCuiL.exe', 'Dashlane.exe', 'OneDrive.exe', 'DashlanePlugin', 'vmtoolsd.exe', 'OUTLOOK.EXE', 'runonce.exe'],
    "mfemms.exe" : ['mfevtps.exe', 'mfehcs.exe', 'mfefire.exe'],
    "masvc.exe" : ['mfemactl.exe'],
    "UpdaterUI.exe" : ['mctray.exe'],
    "runonce.exe" : ['UpdaterUI.exe', 'shstat.exe'],
    "FireSvc.exe" : ['FireTray.exe'],
    "mfeann.exe" : ['conhost.exe'],
    "VsTskMgr.exe" : ['mfeann.exe'],
    "iexplore.exe" : ['iexplore.exe'],
    "cmd.exe" : ['conhost.exe'],
}



# Define a class for a Node in the linked list
class Node:
    def __init__(self, index, pid, ppid, image_file_name):
        self.index = index
        self.pid = pid
        self.ppid = ppid
        self.image_file_name = image_file_name
        self.children = []

# Function to add a child node to a parent node
def add_child(parent, child):
    parent.children.append(child)


# Function to recursively print the tree with '*' depth
def print_tree(node, depth=0):
    if depth > 0:
        print('*' * depth, ' '*(12-depth), end=' ')
    print(f"{node.pid}, {node.ppid}, {node.image_file_name}")
    for child in node.children:
        print_tree(child, depth + 1)


suspect_proc=[]
csv_reader = []
with open('./memory/pslist.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        csv_reader.append(row)

def malproc(node):
    if not node:
        # print('*' * depth, end=' ')
        return
    # print(f"{node.index}, {node.pid}, {node.ppid}, {node.image_file_name}")
    # print(csv_reader[child['Index']]
    #idx = node.index

    #child['ImageFileName'] in normal_proc[process]):
    for child in node.children:
        if not(node.image_file_name in normal_proc and child.image_file_name in normal_proc[node.image_file_name]):
            # print(node.image_file_name, child.image_file_name)            
            suspect_proc.append(csv_reader[child.index])
            
        malproc(child)

# Initialize a dictionary to store nodes by PID




# Read the CSV file and build the linked list
def procTree():
    process_tree = {}

    with open('./memory/pslist.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
            
        for index, row in enumerate(reader):
            pid = int(row['PID'])
            ppid = int(row['PPID'])
            image_file_name = row['ImageFileName']

            # Create a new node if it doesn't exist
            if pid not in process_tree:
                process_tree[pid] = Node(index, pid, ppid, image_file_name)

            # Create a new node for the parent (PPID) if it doesn't exist
            if ppid not in process_tree:
                process_tree[ppid] = Node(-1, ppid, 0, '')  # Use -1 as index for parent nodes

            # Update the image file name for the current node
            process_tree[pid].image_file_name = image_file_name

            # Add the current node as a child to its parent
            add_child(process_tree[ppid], process_tree[pid])

    return process_tree


# Print the tree starting from the root node (PID 4), aligned with the header



def dict2csv(data):
    
    # List of field names
    field_names = data[0].keys()
    
    # Create a list containing the data dictionary
    
    try:
        # Create a StringIO object to hold the CSV data
        output = io.StringIO()
    
        # Write the data to the StringIO object
        writer = csv.DictWriter(output, fieldnames=field_names)
        
        # Write the header
        writer.writeheader()
        
        # Write the data row(s)
        for row in data:
            writer.writerow(row)
    
        # Get the CSV data as a string and print it
        csv_data = output.getvalue()
        print(csv_data)
    
    except Exception as e:
        print("An error occurred:", str(e))

def findrog():
    root_node = procTree()
    malproc(root_node[4])
    dict2csv(suspect_proc)
    #print_tree(root_node[4])

if  __name__ == "__main__":
    findrog()


