import csv

# Open the CSV file for reading
unique_processes = {}
def getsids():
    with open('./memory/getsids.csv', 'r') as csv_file:
        # Create a CSV reader
        csv_reader = csv.reader(csv_file)
        
        # Create a dictionary to store the unique Process rows
        
        # Skip the header row
        next(csv_reader)
        
        # Iterate through the rows in the CSV
        for row in csv_reader:
            # Check if the row is not empty
            if row:
                # Extract the Process value from the row
                process = row[2]  # Assuming Process is in the third column (index 2)
                
                # If the Process is not in the dictionary, add it and store the row
                if process not in unique_processes:
                    unique_processes[process] = row

        # Now, you have the unique rows based on Process in the unique_processes dictionary
    #print_suspecious()
   

unique_sids = {}

# Print the unique rows
def print_sids():
    for row in unique_processes.values():
        # print(','.join(row))  # Join the values of the row into a CSV formatted string

        process = row[2]
        sid = row[3]  # Assuming Process is in the third column (index 2)
            
                # If the Process is not in the dictionary, add it and store the row
        if sid not in unique_sids:
            unique_sids[sid] = []
            

        unique_sids[sid].append(process)
    for sid in unique_sids:
        print('{',sid, ':',unique_sids[sid],'}')

normal_sids = {'S-1-5-18': ['System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'vmacthlp.exe', 
                            'MemCompression', 'spoolsv.exe', 'armsvc.exe', 'HipMgmt.exe', 'masvc.exe', 'FireSvc.exe', 'VsTskMgr.exe', 'mfemms.exe', 
                            'SecurityHealth', 'VGAuthService.', 'vmtoolsd.exe', 'ManagementAgen', 'mfevtps.exe', 'FireTray.exe', 'mfeann.exe', 
                            'macompatsvc.ex', 'mfemactl.exe', 'mfefire.exe', 'mfehcs.exe', 'mcshield.exe', 'OfficeClickToR', 'AppVShNotify.e', 
                            'SearchIndexer.', 'LogonUI.exe'], 
               'S-1-5-96-0-1': ['fontdrvhost.ex'], 
               'S-1-5-90-0-1': ['dwm.exe'], 
               'S-1-5-19': ['macmnsvc.exe'], 
               'S-1-5-20': ['msdtc.exe'], 
               }


# Iterate through the unique_processes dictionary
def print_suspecious():
    for row in unique_processes.values():
        process = row[2]  # Assuming Process is in the third column
        sid = row[3]      # Assuming SID is in the fourth column

        # Check if the SID is not in the normal_sids dictionary
        if sid not in normal_sids:
            if process in normal_sids.get(sid, []):
                print(','.join(row), ' --> Malicious Process: System process running with user account')  # Join the values of the row into a CSV formatted string
            else:
                print(','.join(row))  # Join the values of the row into a CSV formatted string
        else:
            # Check if the process is not in the list of normal processes for the SID
            if process not in normal_sids[sid]:
                print(','.join(row), ' --> Malicious Process: Uknown process running with system account')  # Join the values of the row into a CSV formatted string

getsids()
#print_sids()