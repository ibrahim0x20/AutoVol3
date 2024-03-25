1. Change this help text: "-p path     Path to memory image and csv files like pslist, netscan ..." to 
    "Path to your project directory which have a memory image" 

2. Change this line "No '.img' files found in '/home/ihakami/AutoVol3/memory'" to "No memory image file found in
the directory provided '/home/ihakami/AutoVol3/memory'". Please add a memory image file supported by volatility.
Also change the code part to support all files supported by Volatility too

3. Alos create an md5 hash for the image and save it in the folder. In the next run, calculate the image hash and 
compare it to the one saved in the folder. If chaged ask the user if he want to work with the new image or continue 
with the old one.

4. if os_platform == "":
    print("Unable to determine platform - LOKI is lost.")
    sys.exit(1)

5. Factorization: Split your code to multiple files.
6. Generate the required csv files according the plugins that run

7. Add option to cmmand line --profile (# Find the operating system profile in the memory image
)


1. Identify Anomalous Handles:
            Look for handles with unusual or unexpected types, such as file handles for system files or handles to uncommon objects.
            Pay attention to handles associated with processes that are not part of the normal system configuration.

        2. Examine Handle Counts:
            Check for processes with an unusually high number of handles. This could indicate a process that is performing a lot of file or resource operations, which may be suspicious.

        3. Investigate Suspicious File Handles:
            Focus on file handles and look for processes that have handles to sensitive files, such as system binaries or critical configuration files.
            Cross-reference file handles with file paths to determine if any files are accessed from suspicious locations.

        4. Analyze Network-Related Handles:
            Investigate handles related to network resources, such as sockets or network connections. Look for processes communicating with unusual IP addresses or ports.

        5. Correlate with Process Information:
            Correlate the handles with other process information like process names, PIDs, and parent-child relationships to identify any processes that appear suspicious or out of place.

        6. Check for Code Injection:
            Look for processes that have handles to memory sections with Execute (X) permissions. This could indicate code injection or process hollowing, common techniques used by malware.

        7. Review Timestamps:
            Analyze the timestamps associated with handles. Suspicious processes may have handles with timestamps that don't align with the system's normal behavior.

        8. Cross-Reference with Known Malware Indicators:
            Compare the handles and associated process information with known indicators of compromise (IOCs) and malware signatures to identify matches.

        9. Analyze Parent-Child Relationships:
            Look for unusual parent-child relationships between processes. Malware often spawns child processes to perform malicious activities, so identifying such relationships can be crucial.

        10. Employ YARA Rules:
            Use YARA rules to scan the memory and handles for specific patterns or signatures associated with known malware.

        11. Leverage Threat Intelligence:
            Consult threat intelligence feeds and databases to check if any of the handles or processes are associated with known malware campaigns or threat actors.

        12. Behavioral Analysis:
            Consider the overall behavior of processes with suspicious handles. Look for patterns that deviate from normal system behavior, such as excessive file manipulation or network communication.
        
        Handles represent “pointers” to objects and it is not  unusual for a process to have a pointer to a file it is reading or writing to. However, 
        this is not the common way code is loaded into a process, so it is unusual to see a DLL file referenced in a process handle (recall that loaded
        DLLs are typically referenced in the Process Environment Block and displayed via the windows.dlllist plugin). 
        CLASSES Key Registry
        Storing scripts and data in randomly named registry keys has become a common technique for “fileless” malware, so it pays to keep an eye out strange key

        The interesting handle in the “msiexec.exe” PID 6192 process is a little more obvious. This process only had 16 file handles. If you think about the 
        purpose of “msiexec.exe” (installing .msi files), finding a reference to “flash_installer.msi” likely indicates what was installed on the system. 
        The name and folder location are of particular interest and ultimately led to recovery of the original infection vector.

        Named pipes can be identified via “File” handles in Volatility and thus when narrowing your focus, you can filter your output on that handle type 
        (this was not done in the example on the slide since output was filtered with grep for the text “pipe”).

        However, sometimes things stick out with some connected pipes appending IP addresses or process identifiers as part of the pipe name.

        Malware commonly sets mutants as a way of "marking" a compromised system to prevent reinfection. The malware will first check for the absence of 
        its mutant before performing an infection. During code analysis, reverse engineers can identify what mutant name is set and checked for by the malware. 

    Use Volatility Plugin "windows.timer"

    The filescan plugin allows you to get information about all the files that were encountered in the memory dump, and
    dumpfiles allows you to try to extract these files.
    Use filescan to search for files. Then use dumfiles to dump any file. I have an idea to scan all files in memory. First use filescan and save the result to a text file. Then use grep command to filter on files with extensin at the end with: cat filescan.txt | grep -E  "\.\w+$". Then use dumpfiles to dump all of these files. Or you can use dumfiles without specfying process PID or physaddr option to dump all of them to a folder with option -D <folder name> (vol2)  --> (Not a good option as it produce a huge amount of files most of them are system related)

    Hash the generated files and scan them with VirusTotal and Loki

    


* Build a server to fetch IoCs from VirusTotal, AnyRun, HybridAnalysis, AlianVault....

