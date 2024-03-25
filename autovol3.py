import subprocess
import os
import csv
import sys
from sys import platform as _platform
import traceback
import argparse
import re

#**********************************************************************
#               My Imports
#**********************************************************************

import initialize
import analyze


def print_list(data):
    for pid in data:
        for row in data[pid]:
            print(row)

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
        # if args.debug:
        #     sys.exit(1)


class MalProc(object):
    def __init__(self, project_path):
        self.project_path = project_path 

        self.suspecious_proc =    analyze.is_process_known()
        # ==> Then print suspect_proc from file analyz.py analyze.suspect_proc
        self.suspecious_parent_child = analyze.abnormal_parent_child_process() 
        self.zero_parents = analyze.zero_parents() 
        self.hidden_process = analyze.is_hidden()
        self.privilege_process = analyze.high_privilege()
        self.cmdline = analyze.malcmdline()
        self.suspecious_conn = analyze.malcomm()
        self.maldllls = analyze.maldllls()
        


malproc = MalProc('memory')

for pid in malproc.maldllls:
        for dll in malproc.maldllls[pid]:
            print(dll)
#**********************************************************************
#                       End
#**********************************************************************




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
    handles = {}

    baseline_proc = {}
    evidence_bag = []

    score = {}

  
    

    def __init__(self, image):

        self.image = image
        self.app_path = get_application_path()



        self.initialize_normal_proc(os.path.join(self.app_path, 'normal_proc.txt'))
      

        # The following function must be run the last one
        self.malicious_weight()
        
        
        header = ['Source Name', 'PID', 'PPID','Process Name', 'Path', 'Timestamps', 'Long Description']
        self.evidence_bag.append(','.join(header))

    

#     def collect_evidence(self, pid):
#         """This funtion collects artifacts from all memory objects. This how you can print it print(self.artifact_bag['4'][0]['pslist'])"""
#         #print(self.artifact_bag['4'][0]['pslist'])
#         #print("I will collect artifacts using this funtion!")
#         #print('This is the blueprint for this bag: ioc_collection = [pid: {<plugin1>: <row from plugin csv file>}, {<plugin2>: <row from plugin2 csv file>'+'}]')
#         #self.evidence_bag[4] = [{'pslist':'0,2876,868,WmiPrvSE.exe,0x8c88b14e7580,10,-,0,False,2018-08-30 13:52:26.000000 ,N/A,Disabled'}]

#         # if pid not in self.evidence_bag:
#         #     self.evidence_bag[pid] = []
        
#         # Collect evidence from PsList

#         # reason = 'High privilege account SID: '

#         # if pid in self.getsids:

#         #     if len(self.getsids[pid]) > 1:

#         #         for item in self.getsids[pid]:

#         #             if ('Everyone' in item) or ('Users' in item) or ('This Organization' in item):
#         #                 continue
                    
                
#         #             columns = item.split(',')

#         #             if 'Local System' == columns[4]:
#         #                 reason += ' '.join(columns[3:])


#         #             # Don't forget to add the enrichment from malgetsids function.
#         #             elif '544' in columns[3]:
#         #                 reason += 'The process spawned from a user context with Administrator privileges: '+' '.join(columns[3:])


                    
#         #             if pid in self.suspecious_proc_sids:
#         #                 reason2 = self.suspecious_proc_sids[pid].split(',')
#         #                 if len(reason2) == 6:
#         #                     reason += reason2[5]
#         ppid = ''
#         if pid in self.pslist:
            
#             #print(self.psscan[pid])
#             # evidence = {'pslist': self.pslist[pid]}
#             #self.evidence_bag[pid].append(evidence)
#             row = []
#             row.append('pslist')
#             columns = self.pslist[pid].split(',')
#             row.append(columns[1])

#             ppid = columns[2]
#             row.append(columns[2])
#             row.append(columns[3])

#             path = ''
#             if pid in self.process_path:
#                 path = self.process_path[pid]


#             # You need to change this list because it is not clean, missing a lot of system files and dlls.
#             # if path in self.whitelist_paths and self.score[pid] < 40:
#             #     return

#             row.append(path)
#             row.append(columns[9])        

#             if pid in self.suspect_proc:  
#                 reason = self.suspect_proc[pid].split(',')[11]             
#                 row.append(reason)

#             self.evidence_bag.append(','.join(row))
#         # print(pid, ': ',self.evidence_bag)


#         # Collect evidence from PsScan
#         if (pid in self.psscan) and (pid not in self.pslist):
#             #print(self.psscan[pid])
#             # evidence = {'psscan': self.psscan[pid]}
#             # self.evidence_bag[pid].append(evidence)

#             row = []
#             row.append('psscan')
#             columns = self.psscan[pid].split(',')
#             row.append(columns[1])
#             row.append(columns[2])
#             row.append(columns[3])

#             path = ''
#             if pid in self.process_path:
#                 path = self.process_path[pid]

#             row.append(path)
#             row.append(columns[9])        

#             # 4. Should hidden/Unlinked processes like processes found in psscan, but not in pslist
#             # Hidden processes: Also add more details such as number of threads, parent process, ....
#             if row[1] not in self.pslist:               
#                 row.append('Hidden/Unlinked: The process found in psscan, but not in pslist')
#             self.evidence_bag.append(','.join(row))

#         # Collect evidence from DllList
        
#         if pid in self.dlllist:
            
#             if len(self.dlllist[pid]) > 1:

#                 for item in self.dlllist[pid]:
                    
#                     row =[]
#                     row.append('dlllist')
#                     # evidence = {'dlllist': self.dlllist[pid]}
#                     # self.evidence_bag[pid].append(evidence)
                
#                     columns = item.split(',')

#                     if '.exe' in columns[6]:
#                         continue

#                     # We can add option to use this filtering or not. If we want to find malicious dlls we can use filtering, but
#                     # if we want o understand the malcious process capabilities, we ignore filtering becuase used libraries can tell
#                     # you the malware can do

#                     if columns[6].lower() in self.whitelist_paths:
#                         continue

#                     if self.dll_stacking[columns[6]] > 2:       # Only keep dlls with low frequency as malicious dlls always rare
#                         continue

#                     row.append(columns[1])
#                     row.append(ppid)
#                     row.append(columns[2])
#                     row.append(columns[6])
#                     row.append(columns[7])
#                     row.append('Whitelist the clean DLLs')
#                     self.evidence_bag.append(','.join(row))
#             else:
#                 row =[]
#                 row.append('dlllist')
#                 # evidence = {'dlllist': self.dlllist[pid]}
#                 # self.evidence_bag[pid].append(evidence)

#                 columns = self.dlllist[pid].split(',')
#                 if self.dll_stacking[columns[6]] > 5:       # Only keep dlls with low frequency as malicious dlls always rare
#                     return
#                 row.append(columns[1])
#                 row.append(ppid)
#                 row.append(columns[2])
#                 row.append(columns[6])
#                 row.append(columns[7])
#                 row.append('Whitelist the clean DLLs')
#                 self.evidence_bag.append(','.join(row))
        

#         # Collect evidence from CmdLine
#         if pid in self.cmdline:
#             # evidence = {'cmdline': self.cmdline[pid]}
#             # self.evidence_bag[pid].append(evidence)

#             row =[]
#             row.append('cmdline')       
#             #columns = self.cmdline[pid].split(',')
#             row.append(self.cmdline[pid][0])          # Add pid to the list
#             row.append(ppid)
#             row.append(self.cmdline[pid][1])                    # Add process name
        
#             pattern = r'"?([C|c]:\\[a-zA-Z0-9%\\ \(\)\.]*\.[eE][xX][eE]|[%\\]SystemRoot[%\\][a-zA-Z0-9%\\]*\.exe)\b'            
#             paths = re.findall(pattern, self.cmdline[pid][2])
        
#             if paths:
#                 paths = paths[0].strip('"')
        
#             row.append(path)
#             row.append('')
#             row.append(self.cmdline[pid][2].replace('"', ''))
#             self.evidence_bag.append(','.join(row))


#         if pid in self.netscan:

#             if len(self.netscan[pid]) > 1:

#                 for item in self.netscan[pid]:
#                     row =[]
#                     row.append('netscan')
#                     # evidence = {'dlllist': self.dlllist[pid]}
#                     # self.evidence_bag[pid].append(evidence)
                
#                     columns = item.split(',')
#                     row.append(columns[5])
#                     row.append(ppid)
#                     row.append(columns[6])
#                     row.append(columns[1]+' ' + ' --> '.join(columns[2:4])+' '+columns[4])
#                     row.append(columns[7])
#                     row.append('I Will add info later')
#                     self.evidence_bag.append(','.join(row))
#             else:
#                 # evidence = {'netscan': self.netscan[pid]}
#                 # self.evidence_bag[pid].append(evidence)

#                 row =[]
#                 row.append('netscan')
#                 # evidence = {'dlllist': self.dlllist[pid]}
#                 # self.evidence_bag[pid].append(evidence)

#                 columns = self.netscan[pid][0].split(',')
#                 row.append(columns[5])
#                 row.append(ppid)
#                 row.append(columns[6])
#                 row.append(columns[1]+' ' + ' --> '.join(columns[2:4])+' '+columns[4])
#                 row.append(columns[7])
#                 row.append('I Will add info later')
                
#                 self.evidence_bag.append(','.join(row))

#         if pid in self.getsids:

#             if len(self.getsids[pid]) > 1:

#                 local_system = False
#                 for item in self.getsids[pid]:

#                     if any(keyword in item for keyword in ['Power', 'Logon Session', 'Authentication Authority Asserted Identity', 'PlugPlay', 'Users', 
#                                                            'This Organization', 'Everyone', 'DcomLaunch', 'High Mandatory Level']):
#                         continue
            
#                     row =[]
#                     row.append('getsids')
#                     columns = item.split(',')

#                     if columns[4] == '-':
#                         continue
#                     row.append(columns[1])
#                     row.append(ppid)
#                     row.append(columns[2])
#                     row.append(columns[3])
#                     row.append('')

#                     # Don't forget to add the enrichment from malgetsids function.

#                     reason = columns[4]
#                     if '544' in columns[3]:
#                         reason = 'The process spawned from a user context with high privileges account: ' + reason
                    
#                     if pid in self.suspecious_proc_sids:
#                         reason2 = self.suspecious_proc_sids[pid].split(',')
#                         if len(reason2) == 6:
#                             reason = reason2[5] +': '+ reason
                    
#                     row.append(reason)
#                     self.evidence_bag.append(','.join(row))

#     def create_SuperMemoryParser(self):

#         header = ['Source Name', 'PID', 'Process Name', 'Path', 'Timestamps', 'Long Description']

#         with open('SuperMemoryParser.csv', 'w') as mparser:
#             mparser.write('\n'.join(self.evidence_bag))

#     def malicious_weight(self):

#         if self.pslist:
#             for pid in self.pslist:
#                 weight = 0
#                 if pid in self.suspect_proc:
#                     # if pid =='9036':
#                     #     print(f"Found {pid} in suspect_proc: {self.suspect_proc[pid]}")
#                     weight += 10

#                     if 'Has a zero root parent' in self.suspect_proc[pid]:
#                         weight += 30
                        
                
#                 if pid in self.suspecious_proc_sids:
#                     # if pid =='9036':
#                     #     print(f"Found {pid} in suspecious_proc_sids: {self.suspecious_proc_sids[pid]}")
#                     weight += 10
                    

#                 if pid in self.suspect_cmdlines:
#                     # if '9036' in self.suspect_cmdlines[pid]:
#                     #     print(f"Found {pid} in suspect_cmdlines: {self.suspect_cmdlines[pid]}")
#                     weight += 10

#                 if pid in self.suspect_netscan:
#                     # if pid =='9036':
#                     #     print(f"Found {pid} in suspect_netscan: {self.suspect_netscan[pid]}")
#                     weight += 10
                
#                 # print(self.baseline_proc['1096'])
#                 if pid in self.baseline_proc:
#                     # if pid =='9036':
#                     #     print(f"Found {pid} in baseline_proc: {self.baseline_proc[pid]}")
#                     weight += 10

#                 if weight > 30:
#                     self.score[pid] = weight
                

# def get_application_path():
#     try:
#         if getattr(sys, 'frozen', False):
#             application_path = os.path.dirname(os.path.realpath(sys.executable))
#         else:
#             application_path = os.path.dirname(os.path.realpath(__file__))
#         if "~" in application_path and os_platform == "windows":
#             # print "Trying to translate"
#             # print application_path
#             application_path = win32api.GetLongPathName(application_path)
#         #if args.debug:
#         #    logger.log("DEBUG", "Init", "Application Path: %s" % application_path)
#         return application_path
#     except Exception as e:
#         print("Error while evaluation of application path")
#         traceback.print_exc()
#         if args.debug:
#             sys.exit(1)

# def main(memory):
    
#     """
#     Argument parsing function
#     :return:
#     """
#     # for pid in memory.score:
#     #     print(pid, ': ', memory.score[pid])
    
#     # child_pid = '8260'  # Replace with the PID of the child you want to find the parent for
#     # # parent_node = memory.get_parent(child_pid)

#     # memory.find_parent_recursive(child_pid)
#     # parent_node = memory.get_parent(child_pid)

#     # while parent_node.image_file_name != 'svchost.exe':

#     #     parent_node = memory.get_parent(child_pid)

#     #     if parent_node:
#     #         print(f"Parent PID: {parent_node.pid}, Image File Name: {parent_node.image_file_name}")
#     #     else:
#     #         print(f"No parent found for PID {child_pid}.")

#     #     child_pid = parent_node.pid


#     pid_list = [key for key in memory.score]

#     for pid in pid_list:
#         memory.collect_evidence(pid)
#         #print(pid, ': ', memory.score[pid])
#         # parent = memory.pslist[pid].split(',')[2]

#         memory.find_parent_recursive(pid)

#         # if parent not in memory.score:
#         #     memory.collect_evidence(parent)
    
#     memory.create_SuperMemoryParser()

#     while True:

#         print("Available plugins to explore memory data:")
#         for index, command in enumerate(memory.plugins, start=1):
#             print(f"{index}. {command}")
            
#         print("0. Exit") 
        
#         try:
#             choice = int(input("Enter the plugin number you want to select (or 0 to quit): "))
#             if choice > len(memory.plugins):
#                 print("\nInvalid input. Please enter a valid number.")
#                 continue
#             if choice == 0:
#                 print(memory.score)
#                 break
#             selected_command = memory.plugins[choice - 1]
#             corresponding_file = memory.csv_files[choice - 1]
#             print(f"Selected command: {selected_command}")
#             print(f"Corresponding CSV file: {corresponding_file}")

#             if selected_command == 'pslist':
#                 for pid in memory.pslist:
#                     print(memory.pslist[pid])

#             if selected_command == 'psscan':
#                 for pid in memory.psscan:
#                     print(memory.psscan[pid])

#             if selected_command == 'pstree':
#                 print_process_tree(memory.process_tree['0'])

#             if selected_command == 'dlllist':
#                 for pid in memory.dlllist:
#                     print(memory.dlllist[pid])

#             if selected_command == 'cmdline':
#                 for pid in memory.cmdline:
#                     print(memory.cmdline[pid])

#             if selected_command == 'netscan':
#                 for pid in memory.netscan:
#                     print(memory.netscan[pid])

#             if selected_command == 'getsids':
#                 for pid in memory.getsids:
#                     print(memory.getsids[pid])

#             print("1. Display only suspecious processes")
#             print("2. Continue with full list")
#             print("0. Back") 

#             try:
#                 choice = int(input("Select one option (or 0 go back): "))
#                 if choice == 0:
#                     continue

#                 elif choice == 1:
#                     while True:
#                         print("Display only suspecious processes:")
#                         for index, command in enumerate(memory.analyze, start=1):
#                             print(f"{index}. {command}")
#                         print("0. Back")                        

#                         try:
#                             choice = int(input("Enter the number corresponding to the analysis you want to select (or 0 go back): "))

#                             if choice == 0:                            
#                                 break

#                             elif choice <= len(memory.analyze):
#                                 if choice == 1:
#                                     #suspect_proc = memory.malproc(memory.process_tree['4'])
#                                     for pid in memory.suspect_proc:
#                                         print(memory.suspect_proc[pid])
#                                     print('\n\nThe above processes are more likely the most suspecious processes. Select one of them by PID\n\n')

#                                 elif choice == 3:
#                                     for pid in memory.suspect_cmdlines:
#                                         print(memory.suspect_cmdlines[pid])

#                                 elif choice == 5:
#                                     print('\nThis function have not been implemted, please do it!')
#                                     continue

#                                     suspect_proc = memory.malcomm('blacklist.txt')
#                                     print('\n'.join(suspect_proc))

#                                 elif choice == 6:
#                                     for pid in memory.suspect_netscan:
#                                         print(memory.suspect_netscan[pid])

#                                 elif choice == 7:
#                                     for pid in memory.baseline_proc:
#                                         print(memory.baseline_proc[pid].replace('"', ''))
                                    
#                                 elif choice == 8:
#                                     memory.malgetsids()

#                                     for pid in memory.suspecious_proc_sids:  
#                                         print(memory.suspecious_proc_sids[pid])

#                                 while True:
#                                     # Prompt for the PID to search for
#                                     pid_to_search = input("\n\nEnter the suspecious process PID that you want to collect as evidence (or type 'back' to go back to plugins selection): ")

#                                     if pid_to_search.lower() == 'back':
#                                         break
#                                     memory.collect_evidence(pid_to_search)
#                                             #print(memory.pslist[pid_to_search])

#                             else:
#                                 print("Invalid choice. Please select a valid number.")

#                         except ValueError:
#                             print("Invalid input. Please enter a valid number.")

                        
#                 elif choice == 2:
#                     while True:
#                         # Prompt for the PID to search for
#                         pid_to_search = input("\n\nEnter the suspecious process PID that you want to collect as evidence (or type 'back' to go back to plugins selection): ")

#                         if pid_to_search.lower() == 'back':
#                             break
#                         memory.collect_evidence(pid_to_search)
#                                 #print(memory.pslist[pid_to_search])                    
#                         #print(memory.evidence_bag)
#                 else:
#                     print("Invalid choice. Please select a valid number.")

#             except ValueError:
#                 print("Invalid input. Please enter a valid number.")

#             # for key, value in memory.evidence_bag.items():
#             #     formatted_output = []
#             #     for item in value:
#             #         for entry_type, entry_data in item.items():
#             #             if entry_type == 'dlllist':
#             #                 formatted_output.append(f'{entry_type}:')
#             #                 formatted_output.extend([f'    {line}' for line in entry_data])

#             #             elif entry_type == 'netscan':
#             #                 formatted_output.append(f'{entry_type}:')
#             #                 formatted_output.extend([f'    {line}' for line in entry_data])
#             #             else:
#             #                 formatted_output.append(f'{entry_type}: {entry_data}')
#             #     print("\n".join(formatted_output))  
#             #     print('\n')

#         except ValueError:
#             print("Invalid input. Please enter a valid number.")

# if __name__ == "__main__":

#     # Argument parsing
    
#     # Parse Arguments
#     parser = argparse.ArgumentParser(description='AutVol3 - Simple Memoray Image Analyzer')
#     parser.add_argument('-f', help='Memory image file', metavar='file', default='')
#     parser.add_argument('-p', help='Path to project directory', metavar='path', default='')
#     parser.add_argument('--version', action='store_true', help='Shows welcome text and version of AutoVol3, then exit', default=False)


#     args = parser.parse_args()

#     if not args.p:
#         print('Must specify memory image path!')
#         parser.print_help()
#         sys.exit(1)
 

#     autovol3 = AutoVol3(args)

        
#     #suspect_proc = autovol3.malcomm('blacklist.txt')
#     #autovol3.malgetsids()
#     main(autovol3)      # Change this function name to analyze()

#     #findEvil    

    