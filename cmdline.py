import re

processes = ['smss.exe', 'csrss.exe', 'services.exe', 'lsass.exe', 'spoolsv.exe', 'mfevtps.exe', 'svchost.exe', 'iexplore.exe', 'OUTLOOK.EXE', 
             'VsTskMgr.exe', 'HipMgmt.exe', 'vmacthlp.exe', 'armsvc.exe', 'masvc.exe', 'FireSvc.exe', 'macmnsvc.exe', 'mfemms.exe', 'RuntimeBroker.ex', 
             'vmtoolsd.exe', 'mfeann.exe', 'macompatsvc.exe', 'mfemactl.exe', 'mfefire.exe', 'mfehcs.exe', 'mcshield.exe', 'msdtc.exe', 'UpdaterUI.exe',
             'AppVShNotify.exe', 'explorer.exe', 'RuntimeBroker.exe', 'VGAuthService.exe', 'MSASCuiL.exe', 'SearchIndexer.exe']

normal_paths =[{'c:\\windows\\system32':['smss.exe', 'csrss.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'spoolsv.exe', 'mfevtps.exe', 'msdtc.exe',
                                         'explorer.exe', 'runtimebroker.exe', 'searchindexer.exe']},
                {'c:\\windows':['explorer.exe']},
                {'c:\\program files\\vmware\\vmware tools':['vmacthlp.exe', 'vmtoolsd.exe']},
                {'c:\\program files\\vmware\\vmware tools\\vmware vgauth':['vgauthservice.exe']},
                {'c:\\program files\\internet explorer': ['iexplore.exe']},
                {'c:\\program files\\mcafee\\agent':['masvc.exe', 'macmnsvc.exe']},
                {'c:\\program files\\mcafee\host intrusion prevention':['firesvc.exe']},
                {'c:\\program files\\common files\mcafee\\systemcore': ['mfemms.exe', 'mfefire.exe', 'mfehcs.exe', 'mcshield.exe']},
                {'c:\\program files\\mcafee\\agent\\x86':['macompatsvc.exe', 'mfemactl.exe', 'updaterui.exe']},
                {'c:\\program files\\common files\\microsoft shared\\clicktorun':['appvshnotify.exe']},
                {'c:\\program files\\windows defender':['msascuil.exe']}
                ]
normal_paths_x86 =[{'c:\\program files (x86)\\mcafee\\host intrusion prevention': ['hipmgmt.exe']},
                {'c:\\program files (x86)\\mcafee\\virusscan enterprise': ['vstskmgr.exe']},
                {'c:\\program files (x86)\\microsoft office\\root\\office16':['outlook.exe']},
                {'c:\\program files (x86)\\internet explorer': ['iexplore.exe']},
                {'c:\\program files (x86)\\common files\\adobe\\arm\\1.0':['armsvc.exe']},
                {'c:\\program files (x86)\\mcafee\\virusscan enterprise':['mfeann.exe']},
                ]

no_path = ['wininit.exe', 'winlogon.exe', 'dwm.exe', 'fontdrvhost.exe', 'sihost.exe', 'ctfmon.exe', 'mctray.exe', 'taskhostw.exe', 'LogonUI.exe']

def suspecious():
    with open('./memory/cmdline.csv') as file:
        suspect_cmdlines = []
        cmdline_list = file.read().strip().split('\n')
        for row in cmdline_list:
            if "process exited" in row:
                # Skip lines with 'process exited'
                continue
            
            columns = row.split(',')
            process = columns[2]
            # Check if the process is in the list of processes

            if '.' == process[-1:]:
                process = process + 'exe'
            elif '.e' == process[-2:]:
                process = process + 'xe'
            elif '.ex' == process[-3:]:
                process = process + 'e'

            if process in no_path:
                continue
            elif process in processes:
                process = process.lower()
                if '%SystemRoot%\\system32' in columns[3]:
                    process_path = '%systemroot%\\system32' + '\\' + process
                
                elif '\\SystemRoot\\System32' in columns[3]:
                    process_path = '\\systemroot\\system32' + '\\' + process
                
                elif 'program files (x86)' in columns[3].lower():
                    for path_dict in normal_paths_x86:
                        for path, process_list in path_dict.items():
                            if process in process_list:
                                process_path = path + '\\' + process
                else:
                    for path_dict in normal_paths:
                        for path, process_list in path_dict.items():
                            if process in process_list:
                                process_path = path + '\\' + process

                # Extract the path using regex, considering double quotes
                pattern = r'"?([C|c]:\\[a-zA-Z0-9%\\ \(\)\.]*\.[eE][xX][eE]|[%\\]SystemRoot[%\\][a-zA-Z0-9%\\]*\.exe)\b'            
                paths = re.findall(pattern, columns[3])
                # print(columns[3])
                
                if paths:
                    path = paths[0].strip('"').lower()
                    
                    # Check if the path is exactly in the process_paths
                    if path != process_path:
                        print(process, ': ',process_path)
                        print('RegeEx Path: ',path)
                        suspect_cmdlines.append(row)
                else:
                    # If no path found, consider it suspect
                    suspect_cmdlines.append(row)
            else:
                # If process not in the list, consider it suspect
                suspect_cmdlines.append(row)

    # Print the suspect command-lines
    for cmdline in suspect_cmdlines:
        print(cmdline)


def malcmdline(self):

        no_path = ['wininit.exe', 'winlogon.exe', 'dwm.exe', 'fontdrvhost.exe', 'sihost.exe', 'ctfmon.exe', 'mctray.exe', 'taskhostw.exe', 'LogonUI.exe']

        for pid in self.cmdline:

            process_path = ''

            # Skip lines with 'process exited'
            if "process exited" in self.cmdline[pid] or 'c:\\' not in self.cmdline[pid].lower():
                continue
            
            row = self.cmdline[pid].strip().strip('\n')

            if row =='':
                break

            columns = row.split(',')
            process = columns[2]
            # Check if the process is in the list of processes
            #0,5064,ApplicationFra,"C:\WINDOWS\system32\ApplicationFrameHost.exe -Embedding"

            if '.exe' not in process:
                process = columns[3].split('\\')[-1].split(' ')[0].strip('"')

            if process in no_path:
                continue
            
            if process.lower() in self.normal_process_path:
                process = process.lower()
                if '%SystemRoot%\\system32' in columns[3]:
                    process_path = '%systemroot%\\system32' + '\\' + process
                
                elif '\\SystemRoot\\System32' in columns[3]:
                    process_path = '\\systemroot\\system32' + '\\' + process
                
                elif 'program files (x86)' in columns[3].lower():
                    #process_path = path + '\\' + process
                    for path in self.normal_paths_x86:
                        if process in path:
                            process_path = path
                else:
                    for path in self.normal_paths:
                        if process in path:
                            process_path = path

                 # Extract the path using regex, considering double quotes
                pattern = r'"?([C|c]:\\[a-zA-Z0-9%\\ \(\)\._]*\.[eE][xX][eE]|[%\\]SystemRoot[%\\][a-zA-Z0-9%\\]*\.exe)\b'            
                paths = re.findall(pattern, columns[3])
                # print(columns[3])
                
                if paths:
                    path = paths[0].strip('"').lower()
                    
                    # Check if the path is exactly in the process_paths
                    if path != process_path:
                        self.suspect_cmdlines[pid] = row
                else:
                    # If no path found, consider it suspect
                    self.suspect_cmdlines[pid] = row
            else:
                # If process not in the list, consider it suspect
                self.suspect_cmdlines[pid] = row
        # return suspect_cmdlines  


  # Collect evidence from CmdLine
        if pid in self.cmdline:
            # evidence = {'cmdline': self.cmdline[pid]}
            # self.evidence_bag[pid].append(evidence)

            row =[]
            row.append('cmdline')       
            columns = self.cmdline[pid].split(',')
            row.append(columns[1])
            row.append(ppid)
            row.append(columns[2])
        
            pattern = r'"?([C|c]:\\[a-zA-Z0-9%\\ \(\)\.]*\.[eE][xX][eE]|[%\\]SystemRoot[%\\][a-zA-Z0-9%\\]*\.exe)\b'            
            paths = re.findall(pattern, columns[3])
        
            if paths:
                paths = paths[0].strip('"')
        
            row.append(path)
            row.append('')
            row.append(columns[3].replace('"', ''))
            self.evidence_bag.append(','.join(row))