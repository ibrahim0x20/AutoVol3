import sys
import traceback
import initialize
import os
from sys import platform as _platform
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

project_path = ''

with open('path.txt', 'r') as f:
    project_path =  f.readline().strip()



pslist = initialize.read_pslist(os.path.join(project_path, "pslist.csv"))
psscan = initialize.read_psscan(os.path.join(project_path, "psscan.csv"))
pstree = initialize.new_read_pstree(os.path.join(project_path, "pstree.csv"))
dlllist, dll_stacking, process_path = initialize.read_dlllist(os.path.join(project_path, "dlllist.csv"))
getsids = initialize.read_getsids(os.path.join(project_path, "getsids.csv"))
netscan = initialize.read_netscan(os.path.join(project_path, "netscan.csv"))
cmdline = initialize.read_cmdline(os.path.join(project_path, "cmdline.csv"))
handles = initialize.read_handles(os.path.join(project_path, "handles.csv"))
anomaly_baseline = initialize.read_anomaly_baseline(os.path.join(project_path, "proc_baseline.txt"))

app_path = get_application_path()
signatures = os.path.join(app_path, "signatures")

whitelist = initialize.whitelist(os.path.join(signatures, "whitelist.csv"))
suspect_list = initialize.whitelist("suspecious.csv")

# Must be changed to different function: ==> Read MalwareBazaar
#self.suspect_list = initialize.whitelist(os.path.join(signatures,"suspecious.csv")) 
blacklist_ips = initialize.read_blacklist(os.path.join(signatures,"blacklist.txt"))
regex = initialize.read_regex(os.path.join(signatures,"signatures.txt"))
normal_children = initialize.normal_spawning(os.path.join(app_path,"Win10x64_proc.json"))
normal_sids = initialize.normal_sids("normal_sids.txt")





def malproc(node):

    # 1. Is the process name malicious or normal --> Lookup Applications Database and also for IOC
    #   ==> The same as: Should find processes that don't match whitlist software
    #   ==> Create your own whitelist using tools such as sigcheck.
    #   ==> https://www.circl.lu/services/hashlookup/
    #   ==> If the file path is unknow, check if it as in the next step 
    #   ==> Should find any process that impersonate known processes and trying to blind in with normal processes      ==> Done
    # 2. Should find processes running from weired locations such as unusal directories or temp folders  def malpath()   ==> Done
    # 3. Should find abnormal parent-child relationship                                                                  ==> Done
    # 4. Should find zero parent processes                                      find_processes_without_parents()         ==> Done
    
    # 5. Should find hidden/Unlinked processes like processes found in psscan, but not in pslist                    ==> Done
    # 6. Should find high privilege processes                                                                    ==> Done
    # 7. Suspecious Command Line Arguments
    # 8. Should find processes running from cmd.exe, powershell.exe oe WmiPrvSE.exe
    # 9. Memory baseline
    # 10. Should find processes with high resouce consumption, CPU, memory, network bandwidth
    # 11. Should find processes with persistence mechanisms like autorun, registery entries or scheduled tasks
    # 12. Known Malware Indicator: matching malware process names, LOLbin, file hashes, or network connections to know malware database
    #       - Create your own IoCs for malware or
    #       - Download available databses.
    #       - This database can be applied to dlllist, cmdline, handles, pslist, ...
    # 8. Should find processes that are not digitally signed and verified
    #   ==>  https://github.com/reverseame/sigcheck
    # 6. When does the process start?                                                   ==>TBD
    # 13. Use yarascan plugin and loop through all the Yara signures          
    # 14 Use Tensorflow AI              
                                                                          

 

    print('Analyzing pslist, psscan, and pstree to find malicious processes')


# 1. Is the process name malicious or normal --> Lookup Applications Database and also for IOCs
#   ==> The same as: Should find processes that don't match signed software
# https://www.circl.lu/services/hashlookup/
    
    # Malicious lists:
    #   suspect proc ==> is_process_known()

    # For the plugins output analysis should start with anaomaly_baseline.txt file

def is_process_known():
    # Verify if the process file path is in the whitelist                                   ===> Done
    #       Your whitelist file is not great <==> It is great, but you don't know how to use it --> File ptah ID solve the problem
    #   Verify if the process name is in the file path found in the dlllist (process_path)    ===> Done
    #   Why I came with hash value look up --> fast search algorithm o(n) instead of O(n*m)
    #   This part of the new code solve two problems from the previous in one place:  
    #   ==> def malpath() and one statement in 
    #   ==> collect_evidence() function: 
    #   if columns[6].lower() in self.whitelist_paths:
    #       continue
    
    for pid in process_path:

        suspect_proc = {}

        ImageFileName = pslist[pid].split(',')[3]
        if ImageFileName not in process_path[pid]:      # Is the process name is in the file path?
            suspect_proc[pid] = pslist[pid][2:] + ', ' + process_path[pid] + ', Process Hallowing - Process name is not the same as in the file path'
            continue
        
        id = initialize.path_id(process_path[pid])
        if id in whitelist:
            continue
        else:
            suspect_proc[pid] = pslist[pid][2:] + ', ' + process_path[pid] + ', Unkown file path'

    return suspect_proc
    # 3. Should find abnormal parent-child relationship
    

# pslist = initialize.read_pslist("memory/pslist.csv")
# psscan = initialize.read_psscan("memory/psscan.csv")
# process_tree = initialize.read_pstree("memory/pstree.csv")
# #initialize.print_process_tree(process_tree)
# dlllist, dll_stacking, process_path = initialize.read_dlllist("memory/dlllist.csv")
# getsids = initialize.read_getsids("memory/getsids.csv")
# netscan = initialize.read_netscan("memory/netscan.csv")
# normal_children = initialize.normal_spawning("Win10x64_proc.json")

# whitelist = initialize.whitelist ("whitelist.csv")
# suspect_list = initialize.whitelist("suspecious.csv")


# normal_sids = initialize.normal_sids("normal_sids.txt")
# cmdline = initialize.read_cmdline("memory/cmdline.csv")
# handles = initialize.read_handles("memory/handles.csv")
# regex = initialize.read_regex("signatures.txt")
# blacklist_addresses = initialize.read_blacklist("blacklist.txt")
# anomaly_baseline = initialize.read_anomaly_baseline("memory/proc_baseline.txt")


suspect_proc = {}

# # 3. Should find abnormal parent-child relationship
def abnormal_parent_child(node):

    if not node:
        return #suspect_proc

    for child in node.children:
        if not(node.image_file_name in normal_children and child.image_file_name in normal_children[node.image_file_name]):
            # print(node.image_file_name, child.image_file_name)            
            suspect_proc[child.pid] = pslist[child.pid][2:] + ', Suspecious parent-child relationship'
            
        abnormal_parent_child(child)


# This function using the tree created with function build_tree_from_data()
def new_abnormal_parent_child(node):
    
    for child in node.children:
        #print(f"{node.data[2]}:{child.data[2]}")
        if not(node.data[2] in normal_children and child.data[2] in normal_children[node.data[2]]):
            #print(node.image_file_name, child.image_file_name)            
            suspect_proc[child.data[0]] = pslist[child.data[0]] + ', Suspecious parent-child relationship'
            #print(suspect_proc[child.data[0]])
        new_abnormal_parent_child(child)

# # def spawning_process():     
def abnormal_parent_child_process():
    new_abnormal_parent_child(pstree[0])
          
def zero_parents():

    zero_parents_process = {}
    for root_node in pstree[1:]:

        zero_parents_process[root_node.data[0]] = pslist[root_node.data[0]] + ', Process with no parent'

    return zero_parents_process

#   # 4. Should hidden/Unlinked processes like processes found in psscan, but not in pslist
#             # Hidden processes: Also add more details such as number of threads, parent process, ....
def is_hidden():

    hidden_proc = {}
    for pid in psscan:
        if pid not in pslist:  
            hidden_proc[pid]   =   psscan[pid] + ', Hidden/Unlinked: The process found in psscan, but not in pslist'  
    
    return hidden_proc


def high_privilege():
    
    sid_processes = []

    high_privilege_proc = {}

    for sid in normal_sids:
        for process in normal_sids[sid]:
            if process not in sid_processes:
                sid_processes.append(process)

    for pid in getsids:
        columns = getsids[pid][0].split(',')
        sid = columns[2]
        process = columns[1]

        if sid not in normal_sids:
            # #print(sid)
            # for tmpSid in normal_sids:
            #     #if process in normal_sids.get(sid, []):
            #     if process in normal_sids[tmpSid]:
            if process in sid_processes:

                high_privilege_proc[columns[1]] = getsids[pid][0], ' --> Malicious Process: System process running with a user account'  # Join the values of the row into a CSV formatted string

        else:
#                 # Check if the process is not in the list of normal processes for the SID
            if process not in normal_sids[sid]:
#                     row.append('Malicious Process: Uknown process running with system account')
#                     self.suspecious_proc_sids[pid] =','.join(row)
                high_privilege_proc[columns[1]] = getsids[pid][0], ' --> Uknown process running with ', columns[3]


    return high_privilege_proc


def malcmdline():
    # 1. Verify if the process normal 
    #   ==> Use the process PID and look it up in the suspect_proc list from function is_process_known()
    #   ==> This does not mean the process is compeletely normal, but verifies that  process name and path is OK
    #       ==> For now, I think this step is useless and dose not make sense for me because all the processe are in pslist
    #       ==> After one day from the above line was written, today it clicked with me and does make sense.
    #           => I have to extract the path and process name and see if they are running from normal locations 
    #              using whitelist.csv or you can use the list suspect_proc from is_know_process()
    #           => After verifying the path location, we can use the next step 2.
    # 2. Find processes runing from cmd.exe or powershell.exe
    #   ==> When cmd.exe executed, it will create a process. search for this process and add it to the list. 
    #   ==> If not found in cmdline list, look for it in psscan list
    #   ==> You should also create the same for powershell.exe, wscript.exe, wmiprvse.exe, rundll32.exe, dllhost.exe, 
    #   ==> svchost, msiexec.exe...
    #   ==> Use regex to search for patteren matches
 
    # 4. Analyze Command History: Examine the command history for each process. Pay attention to commands that are unusual, 
    #   potentially indicative of malicious activity, or related to system compromise. Commands related to downloading or 
    #   executing files, modifying system settings, accessing sensitive information, or connecting to external hosts are 
    #   often of interest.
    # 5. Check for Evasion Techniques: Malicious actors often attempt to hide their activities by using techniques such as 
    #   obfuscated commands, using legitimate system tools in unexpected ways, or deleting command history. Look for signs of 
    #   such techniques in the command history.
    # 6. Correlate with Other Artifacts: Cross-reference the command history with other artifacts extracted from the memory dump 
    #   or the system, such as network connections, file system activity, registry changes, and process memory. This can provide 
    #   additional context and help confirm suspicions.
    # 7. Look for Persistence Mechanisms: Identify any commands or processes that may indicate attempts to establish persistence 
    #   on the system, such as creating scheduled tasks, modifying startup configurations, or installing new services.
    # 8. Search for Indicators of Compromise (IOCs): Look for known indicators of compromise, such as file hashes, IP addresses, 
    #   domain names, or specific command patterns associated with known malware or attack techniques.
    # 9. Correlate with External Threat Intelligence: If available, cross-reference your findings with external threat 
    #   intelligence sources to identify known malicious activities or patterns associated with specific threat actors or malware families.
    # 10. Privilege escalation: Look for commands that elevate privileges.
    
    # 12. Suspicious Arguments:



    suspect_cmdlines = {}

    # At the beginning, we can look for LOLbin tools and malware
    # 11. Known Malware Tools: Research tools commonly used by malware for tasks like:
    #   - Downloading files (e.g., wget, curl)
    #   - File manipulation (e.g., copy, move, delete) with suspicious paths
    #   - Registry access tools (e.g., reg add, reg delete)
    #   - Lateral movement tools (e.g., PsExec, ssh) used to move within a network
    #   - Process manipulation tools (e.g., taskkill, powershell) used to terminate or inject code


    # Focus your analysis only on the anaomaly_baseline list. Skip the cmdline list.

    for pid in anomaly_baseline:
        
        #args = cmdline[pid][2]

        #if pid in anomaly_baseline:     # This is also useless, because we only need to focus on what in anomaly_baseline
            #print(baseline_list[pid])
                
            #args = args.replace("%SystemRoot%", "C:\\Windows").replace("\\SystemRoot", "C:\\Windows")

            #if 'process exited' in args or 'c:\\' not in args.lower():
                #print(cmdline[pid][1])
                #continue

            for row in anomaly_baseline[pid]:

                #args = args.replace('"', '').strip()
                if '.exe' in row.split('|')[5]:
                    args = row.split('|')[4].replace('"', '').strip()

                #if args in row:  <== This is useless, because what is in anomaly_baseline is actually in cmdline. We don't need this.
        
                # Extract the cmdline path using regex. ==> I extracted the path, but again I don't know how to get deal of it.
                # Just leave for now
                pattern = r'"?([\\?]*[C|c]:\\[a-zA-Z0-9%\\ \(\)\.-_+]*\.[eE][xX][eE])\b'            
                match = re.match(pattern, args)
                
                # You actually have to work on verifying the path of the executed command and its parameters.
                if match:
                    path = match[0].strip('"') 

                # Use regex to find malicious cmdline        
                # Iterate through each regex pattern
                for regex_pattern in regex:
                    match = re.search(regex_pattern, args)
                    if match:
                        path_executed = match.group(0)

                        if pid not in suspect_cmdlines:
                            suspect_cmdlines[pid] = cmdline[pid]
                        #matched_paths.append(path_executed)

                        for child_pid in pslist:
                            if pid in pslist[child_pid].split(',')[1]:
                                
                                # From here, we can look if powershell running cmd.exe or
                                #   if wmic running powershell
                                suspect_cmdlines[pid] = cmdline[pid]

                                if child_pid in cmdline:
                                    suspect_cmdlines[child_pid] = cmdline[child_pid]
                                else:
                                    suspect_cmdlines[child_pid] = pslist[child_pid]
    return suspect_cmdlines


# def malhandles():
#     # 1. Identify Anomalous Handles:
#     #     Look for handles with unusual or unexpected types, such as file handles for system files or handles to uncommon objects.
#     #     Pay attention to handles associated with processes that are not part of the normal system configuration.

#     # 2. Examine Handle Counts:
#     #     Check for processes with an unusually high number of handles. This could indicate a process that is performing a lot of 
#     #   file or resource operations, which may be suspicious.

#     # 3. Investigate Suspicious File Handles:
#     #     Focus on file handles and look for processes that have handles to sensitive files, such as system binaries or critical
#     #    configuration files.
#     #     Cross-reference file handles with file paths to determine if any files are accessed from suspicious locations.

#     # 4. Analyze Network-Related Handles:
#     #     Investigate handles related to network resources, such as sockets or network connections. Look for processes 
#     #     communicating with unusual IP addresses or ports.

#     # 5. Correlate with Process Information:
#     #     Correlate the handles with other process information like process names, PIDs, and parent-child relationships to 
#     #   identify any processes that appear suspicious or out of place.

#     # 6. Check for Code Injection:
#     #     Look for processes that have handles to memory sections with Execute (X) permissions. This could indicate code injection 
#     #   or process hollowing, common techniques used by malware.

#     # 7. Review Timestamps:
#     #     Analyze the timestamps associated with handles. Suspicious processes may have handles with timestamps that don't align 
#     #   with the system's normal behavior.

#     # 8. Cross-Reference with Known Malware Indicators:
#     #     Compare the handles and associated process information with known indicators of compromise (IOCs) and malware signatures
#     #    to identify matches.

#     # 9. Analyze Parent-Child Relationships:
#     #     Look for unusual parent-child relationships between processes. Malware often spawns child processes to perform malicious
#     #    activities, so identifying such relationships can be crucial.

#     # 10. Employ YARA Rules:
#     #     Use YARA rules to scan the memory and handles for specific patterns or signatures associated with known malware.

#     # 11. Leverage Threat Intelligence:
#     #     Consult threat intelligence feeds and databases to check if any of the handles or processes are associated with known 
#     #   malware campaigns or threat actors.

#     # 12. Behavioral Analysis:
#     #     Consider the overall behavior of processes with suspicious handles. Look for patterns that deviate from normal system 
#     #   behavior, such as excessive file manipulation or network communication.
    
#     # Handles represent “pointers” to objects and it is not  unusual for a process to have a pointer to a file it is reading or 
#     #   writing to. However, 
#     # this is not the common way code is loaded into a process, so it is unusual to see a DLL file referenced in a process handle 
#     #   (recall that loaded
#     # DLLs are typically referenced in the Process Environment Block and displayed via the windows.dlllist plugin). 
#     # CLASSES Key Registry
#     # Storing scripts and data in randomly named registry keys has become a common technique for “fileless” malware, so it pays 
#     # to keep an eye out strange key

#     # The interesting handle in the “msiexec.exe” PID 6192 process is a little more obvious. This process only had 16 file 
#     # handles. If you think about the 
#     # purpose of “msiexec.exe” (installing .msi files), finding a reference to “flash_installer.msi” likely indicates what was 
#     # installed on the system. 
#     # The name and folder location are of particular interest and ultimately led to recovery of the original infection vector.

#     # Named pipes can be identified via “File” handles in Volatility and thus when narrowing your focus, you can filter your 
#     # output on that handle type 
#     # (this was not done in the example on the slide since output was filtered with grep for the text “pipe”).

#     # However, sometimes things stick out with some connected pipes appending IP addresses or process identifiers as part of 
#     # the pipe name.

#     # Malware commonly sets mutants as a way of "marking" a compromised system to prevent reinfection. The malware will first 
#     # check for the absence of its mutant before performing an infection. During code analysis, reverse engineers can identify 
#     # what mutant name is set and checked for by the malware. 

#     # # Stack handles too. Look for the file handle path if it is normal. Look for thr egistry key handles if it is refencing 
#     # a file 
#     #pattern = r'\.dll(?!\.mui)'

#     # Explain this point and give me an example: Write Access to Critical Files: Handles with write access to system files, configuration files, or user data folders. 

#     # Here's a deeper explanation of the point "Write Access to Critical Files" when analyzing file handles with Volatility's handles plugin, along with an example:

#     # Why Critical Files Matter:

#     #     System Stability: System files are essential for the proper functioning of the operating system. Modifying them can lead to crashes, instability, or unexpected behavior.
#     #     Security Configuration: Configuration files hold sensitive information about system settings and security policies. Malware might try to modify these files to disable security measures or gain persistence.
#     #     User Data Privacy: User data folders contain personal information like documents, emails, or browsing history. Malicious actors might try to access or modify these files for various malicious purposes.

#     # Identifying Suspicious Write Access:

#     # When examining the handles plugin output, look for entries where:

#     #     Process: The handle is associated with a process with an unknown name or a history of being linked to malware. You can use other Volatility plugins or external resources to research the process.
#     #     Granted Access: The handle has "Write" or "ReadWrite" access (indicated by values like 0x1F0089 or 0x3F0089). This allows the process to modify the file contents.
#     #     File Path: The handle points to a file in a critical location, such as:
#     #         System directories (e.g., C:\Windows\System32)
#     #         Configuration folders (e.g., C:\Windows\System32\config)
#     #         User data directories (e.g., C:\Users\<username>\Documents)

#     # Example:

#     # Here's a simulated example of a suspicious handle entry:

#     # TreeDepth   PID   Process   Offset   HandleValue   Type   GrantedAccess   Name   
#     # 0   3456   Unknown   0x12345678   0xABCDEF00   File   0x3F0089   C:\Windows\System32\drivers\etc\hosts

#     # This example shows a handle with concerning details:

#     # Unknown Process: The handle is associated with a process named "Unknown," which could indicate potential malware as 
#     #    legitimate processes typically have identifiable names.
#     #     Write Access: The granted access is "ReadWrite" (0x3F0089), allowing the process to modify the file content.
#     #  File: The file path points to the system hosts file, which is used to map hostnames to IP addresses. 
#     #   Modifying this file could be used to redirect traffic to malicious websites (e.g., phishing attacks).

#     #     What if there is a handle to .dll file?

#     # A handle to a .dll file in the handles plugin output can be a sign of normal operation or potentially suspicious activity, 
#     # depending on the context. Here's a breakdown:

#     # Normal Scenarios:

#     #     Loading DLLs: Applications often load DLLs (Dynamic Link Libraries) to extend their functionality. When a program loads 
#     # a DLL, the operating system assigns a handle to manage access. This is a normal behavior.
#     #     DLL Injection: Legitimate software might also use DLL injection techniques to extend functionality dynamically. 
#     # In this case, the injected DLL would have a handle associated with it.

#     # Suspicious Scenarios:

#     #     Unknown DLLs: If the handle points to a DLL with an unfamiliar name and located in an unusual path (e.g., user folders,
#     # temporary directories), it could be a sign of malware loading a custom DLL for malicious purposes.
#     #     Multiple Handles: Processes typically only need one handle to access a loaded DLL. Multiple handles to the same DLL,
#     # especially from unknown processes, could be suspicious.
#     #     High CPU/Memory Usage: If a process with a handle to a DLL is also consuming a high amount of CPU or memory resources, 
#     # it might indicate the DLL is performing malicious activity.

#     # What to Look For:

#     # When analyzing a handle pointing to a DLL in the handles plugin output, consider these factors:

#     #     Process: Identify the process associated with the handle. Is it a known and legitimate program, or an unknown process?
#     #     DLL Path: Where is the DLL located? Is it in a standard system directory (e.g., C:\Windows\System32) or a suspicious 
#     # location?
#     #     Multiple Handles: Are there multiple handles to the same DLL from different processes?
#     #     Process Behavior: Is the process with the handle exhibiting any other suspicious behavior, like high resource usage or 
#     # network activity?

#     # Additional Tips:

#     #     Research DLL Names: If the DLL name is unfamiliar, research it online to see if it's associated with known malware or legitimate software.
#     #     Correlate with Other Findings: Combine information from the handles plugin with findings from other Volatility plugins for a more comprehensive picture. Analyze network connections, loaded modules, and process behavior.


#     # GrantedAccess column is tooooooo important (read/write permissions)


#     pattern = r'\.dll$'

#     for pid in handles:
#         for row in handles[pid]:
#             #print(row)
#             if re.search(pattern, row[6]):
#                 print(row)
            
#             if '.msi' in row[6]:
#                 print(row)

#             if 'NamedPipe' in row[6]:
#                 print(row)

#     print('Here will goes handles function')



def malcomm():

    # Add option for VPN concentrator

    suspect_netscan = {}
    # Define the browser processes you want to exclude
    browsers = ["chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe"]  # Add more if needed
    #print(netscan)
    for pid in netscan:
        suspect_comm = []

        for item in netscan[pid]:
            row = item.split(',')
            

            
            if 'WinStore.App.e' in row[6]  or 'OneDrive.exe' in row[6] or 'SearchUI.exe' in row[6]:
                continue
                    

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
                    suspect_comm.append(','.join(row) + ', A process that is not browser using port: '+foreign_port)

                
                # 2. Any browser process not communicating over port 80, 443, or 8080
                elif any(browser in owner for browser in browsers) and foreign_port not in ["80", "443", "8080"]:
                    suspect_comm.append(','.join(row)+ ', A browser communicating over unusual port: '+ foreign_port)

                # 3. RDP connections (port 3389), particularly if originating from odd IP addresses. External RDP
                # connections are typically routed through a VPN concentrator. If the src_ip is not from a VPN concentrator, this is malicious
                #and not src_ip.startswith(("*", "::", "0.0.0.0", "127.0.0.1", "172.16.", "192.168."))
                elif foreign_port == "3389" :
                    suspect_comm.append(','.join(row)+', IP communicating with RDP port')

                # 4. Connections to unexplained internal or external IP addresses. 
                # External resources like IP reputation services can also provide additional context.
                elif dst_ip in blacklist_ips:
                    suspect_comm.append(','.join(row) + ', Black listed IP' )

                elif foreign_port in ["5985", "5986"] and not dst_ip.startswith(("0.0.0.0", "127.0.0.1")):
                    suspect_comm.append(','.join(row)+ ', Powershell remote session using WinRM')
                
                # 7. Workstation to workstation connections. Workstations don’t typically RDP, map shares, or authenticate to other workstations. 
                # The expected model is workstations communicate with servers. Workstation to workstation connections often uncover lateral movement. 
                
                elif ((src_ip.startswith("172.16.") and dst_ip.startswith("172.16.")) or \
                        (src_ip.startswith("192.168.") and dst_ip.startswith("192.168."))):
                    suspect_comm.append(','.join(row)+', Workstation to workstation communication')


        # suspect_comm is a temp variable collect suspecious procs for every for loop. At the end of every for loop it add the result to suspect_netscan.
        if suspect_comm:
            # if pid not in suspect_netscan:
            #     suspect_netscan[pid] = []
            suspect_netscan[pid] = suspect_comm
    # for pid in suspect_netscan:
    #     for row in suspect_netscan[pid]:
    #         print(row)
    return suspect_netscan



def diff_signed():

    # 1. To get better baseline, consider first installing all the required application on your system and run all of these 
    #   applications and then take a memory image for your system as a golden image, and also take sigcheck. 
    # 2. Genearte a Golden sigcheck.exe after installing all the required applications
    # 3. After incident, generate Suspecious sigcheck.exe
    # 4. Find the difference between the two list
    # 5. Use this list to find dll injection, file hash

     

    diff = {}

    for id in suspect_list:
        if id not in whitelist:
            diff[id] = suspect_list[id]

    return diff


signed_diff = diff_signed()
 
def maldllls():
    # 1. Start the analysis with baseline. Any thing deviate from the baseline consider more invistigation on it.   ==> Done
    # 2. Correlate the diff from baseline with the witelist.csv (Generated by sigcheck.exe from Golden system).     ==> Done
    # 3. Any dlls that in the memory, but not on the disk(Use sigcheck.exe to generate another list after memory dump. 
    #   ==> This list is different than the whitelist.csv. This list generated after suspecious activity.  
    #   ==> The idea here is to find the process hallowing or code injection)
    #   ==> Also, this generated sigcheck, can be compared with the Golden one.
    #   ==> In addition, we can use it to find the Hash of dlls and processes found in diff from baseline
    # 4. To get better baseline, consider first installing all the required application on your system and run all of these 
    #   applications and then take a memory image for your system as a golden image, and also take sigcheck.  
    # 5. Should this dll  run under this process or not?

    # 6. Review Known Malicious DLLs: Cross-reference the listed DLLs against known malicious DLLs. You can use threat 
    #   intelligence sources, malware analysis reports, or online databases to identify DLLs associated with malware or 
    #   known attacks.

    # 7. Analyze Process Context: Consider the context of the process. Is it a system process, a user process, or one spawned 
    #   by another process? Malicious processes often masquerade as legitimate ones, so understanding the context can help 
    #   identify anomalies.

    # 8. Check DLL Loading Behavior: Look for abnormal DLL loading behavior, such as DLLs loaded from unusual or unexpected locations, 
    #     particularly from temporary directories or network shares. Also, examine whether any DLLs are loaded with suspicious flags 
    #         or permissions.

    # 9. Identify Code Injection: Look for evidence of code injection techniques, such as reflective DLL injection or process hollowing. 
    # This can manifest as unusual DLLs loaded into legitimate processes or unexpected memory sections within a process's address space.

    # 10. Analyze Dependencies: Examine the dependencies of loaded DLLs. Malware often injects its code into legitimate processes by 
    # loading malicious DLLs that depend on legitimate system DLLs. Identifying such dependencies can reveal suspicious activity.

    # 11. Behavioral Analysis: Consider the behavior of the process in conjunction with the loaded DLLs. Look for processes exhibiting 
    # suspicious behavior such as persistence mechanisms, network communication, or attempts to access sensitive system resources.

    # 12. Timeline Analysis: Compare the DLL loading activity across different memory snapshots to identify changes or anomalies over 
    # time. Malicious processes may dynamically load and unload DLLs to evade detection.

    # 13. LoadTime can help detect DLL injection

    diff_dll = {}


    for pid in anomaly_baseline:
        for row in anomaly_baseline[pid]:
            columns = row.split('|')

            # dll_name = columns[5].replace('"', '').strip()
            # if '.exe' not in dll_name:
                
            dll_path = columns[6].replace('"', '').strip()

            id = initialize.path_id(dll_path)

            # Is the deviated processes or dlls(diff_baseline) in the signed files list(White list,) if not, it is suspecious
            # This step is just to minimize noise. May be during the golden memory baseline, the dlls or exe was not in memory,
            # But, the sigchech.exe will add all the files on the disk to the whitelist.csv
            if id not in whitelist:

                # suspect_proc[pid] = pslist[pid][2:] + ', ' + process_path[pid] + ', Unkown file path'

                
    
                # 3. Any dlls that in the memory, but not on the disk(Use sigcheck.exe to generate another list after memory dump. 
                #   ==> This list is different than the whitelist.csv. This list generated after suspecious activity (suspecious.csv).  
                #   ==> The idea here is to find the process hallowing or code injection)
                #   ==> Also, this generated sigcheck, can be compared with the Golden one to produce diff_signed.
                #   ==> In addition, we can use it to find the Hash of dlls and processes found in dll_diff from baseline
                #   a. Generate a diff_signed list: the difference between the Golden Signed list(whitelist.csv) and the 
                #       suspecious list(Genereted sigcheck.exe after suspecious activity)                                   ==> Done
                #   b. Look up the dlls and exe in the diff_signed. If the file not found, that mean dll injection. If found,
                #       collect the file info. If it is signed, skip it. if not, grep the file hash and look it up on VirusTotal
                #   c. If the file not found on disk, use windows.dumpfiles to extract it, and then hash it and look it up
                #       on VirusTotal

                if id not in signed_diff:       # Check if the dll in memory also on disk? 
                    # Dump the file with windows.dumpfiles plugin
                    print('Dll injection!')

                    if pid not in diff_dll:
                        diff_dll[pid] = []
                    diff_dll[pid].append(','.join(columns))
                else:
                    # Is the file signed
                    if 'Signed' == signed_diff[id][1]:
                        # Add this process in diff_baseline to the Golden Memory baseline
                        print('Add this process to the baseline!')
                        
                        continue
                    else:
                        hash256 = signed_diff[id][14]
                        print(hash256)
                        # Check VirusTotal
                        # If the hash256 clean, add this process to the Golden Memory baseline


    return diff_dll



# csv_file = "memory/pstree.csv"
# root_nodes = initialize.new_read_pstree(csv_file)
        


# for node in pstree:
#     print(node)
#print(pstree[1])
#malhandles()

#is_hidden()
#print(normal_sids)
#print(getsids)
#print(malcmdline())
#print(regex)                    

# for pid in suspect_proc:
#     print(suspect_proc[pid])
# print(malcmdline())

#diff("memory/proc_baseline.txt")
# malcomm()
#diff()
#print(dll_stacking)
maldllls()
#diff_signed()
    
