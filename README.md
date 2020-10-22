# Linux-CatScale IR Collection Script 

Linux CatScale is a bash script that uses live of the land tools to collect extensive data from Linux based hosts. The data aims to help DFIR professionals triage and scope incidents. An Elk Stack instance also is configured to consume the output and assist the analysis process. 

- [Usage](#usage)
- [Parsing](#parsing)
- [What does it Collect](#what-does-it-collect)
- [Disclaimer](#disclaimer)
- [Tested OSes](#tested-oses)


## Usage

This scripts were built to automate as much as possible. We recommend running it from an external device/usb to avoid overwriting evidence. Just in case you need a full image in future. 

Please run the collection script on suspected hosts with sudo rights. fsecure_incident-response_linux_collector_0.7.sh the only file you need to run the collection. 

```
user@suspecthost:<dir>$ chmod +x ./Cat-Scale.sh
user@suspecthost:<dir>$ sudo ./Cat-Scale.sh 
```

The script will create a directory called "FSecure-out" in the working directory and should remove all artefacts after being compressed. This will leave a filename in the format of `FSecure_Hostname-YYMMDD-HHMM.tar.gz` 

Once these are all aggregated and you have the `FSecure_Hostname-YYMMDD-HHMM.tar.gz` on the analysis machine. You can run Extract-Cat-Scale.sh which will extract all the files and place them in a folder called "extracted".

```
user@analysishost:<dir>$ chmod +x ./Extract-Cat-Scale.sh
user@analysishost:<dir>$ sudo ./Extract-Cat-Scale.sh
```

### Parsing

This project has predefined grok filters to ingest data into elastic, feel free to modify them as you need. 

The indexes are split into snap-\* indicating a snapshot of data taken at the time of running the script and varlog-\* which indicates data came from a log source

To view the newly imported data: click on the management/gear icon -> Index Patterns and select the index you would like to import. These have been exported and can be found under the kibana folder. Click on management/gear icon, Saved Objects, import and select "CatScale-index-patterns.ndjson" from the kibana folder. Initial searches, visualisations and dashboards can also be imported from this folder.


## What does it collect?

This script will procude the following files/folders which can be reviewed as text files or using Elk Stack.

```
bash_history                    - Bash history for all users
bash_profile                    - Bash profile file for all users
bash_rc                         - Bash_rc file
full-timeline.csv               - Timeline of all files in the following directories: /home/* + var/www/* + /tmp/ + /dev/shm/ + /bin + /sbin
bin-dir-timeline                - Timeline of all files in /bin
binhashes.txt                   - Hash of all executable files under $PATH variable
btmp-lastlog.txt                - btmp last log
console-error-log.txt           - This were all the errors from the script is forwarded to
cpuinfo.txt                     - CPU info
dev-shm-dir-timeline            - Timeline of all files in /dev/shm/
df.txt                          - Information about the file system on which each FILE resides,or all file systems by default.
dhcp.txt                        - Resolver configuration file resolv.conf
executables-list.txt            - All ELF files on disk with +x attribute
group.txt                       - List of groups and the members belonging to each group
home-dir-timeline               - Timeline of all files in /home/*
host.conf.txt                   - Resolver configuration file host.conf
hosts.allow.txt                 - Host access control file hosts.allow
hosts.deny.txt                  - Host access control file hosts.deny
hosts.txt                       - Static table lookup for hostnames /etc/hosts
ifconfig.txt                    - ifconfig -a Output
iptables.txt                    - Tables of IPv4 and IPv6 packet filter rules in the Linux kernel.
lastbad.txt                     - Records failed login attempts
lastlog.txt                     - The most recent login of all users or of a given user
last.txt                        - History of all logins and logouts
lsmod.txt                       - Kernel modules are currently loaded
lsof-processes.txt              - List of all open files and the processes that opened them.
lsusb.txt                       - Attached USB device info
md5-ps.txt                      - ps command bin md5
meminfo.txt                     - Memory info
netstat-ano.txt                 - Listing All Sockets, in numeric form with timer info
netstat-antup.txt               - All tcp/udp connection in numeric form with process ID
netstat-list.txt                - All tcp/udp connection in numeric form with process ID without headers
num-proc.txt                    - number of processes according to ps command
num-ps.txt                      - number of processes according to /proc directory
package-list.txt                - All files in all rpm packages
packages-result.txt             - all executables that are not part of rpm packages
passwd.txt                      - Copy of the passwd file
persistence-anacron.txt         - All Anacron jobs
persistence-cronlist.txt        - All Cron jobs
persistence-initd.txt           - All initd scripts
persistence-profiled.txt        - Scripts that run when User logs in
persistence-rc-scripts.txt      - All rc scripts. (run level scipts)
persistence-shellrc-etc.txt     - All startup script contents in /etc/
persistence-shellrc-home.txt    - All startup script contents in /home/
persistence-shellrc-root.txt    - All startup script contents in /root/
persistence-systemdlist.txt     - All systemd services and execution commandlines
process-details.txt             - All running process details and status information
processes-list.txt              - All running process acording to ps
processes.txt                   - All running process acording to /proc/ directory
processhashes.txt               - Hash of all running processes
procmod.txt                     - Loaded modules for all processes
release.txt                     - OS information
routetable.txt                  - Contents of kernel routing table. route command output
sbin-dir-timeline               - Timeline of all files in /sbin/*
service_status.txt              - All running service and their status.
ssh_config.txt                  - ssh service config file
sshd_config.txt                 - ssh service config file
sudoers.txt                         - List of sudoers
tmp-dir-timeline                    - Timeline of all files in /tmp/*
tmp-executable-files-for-diff.txt   - tmp-executable-files.txt without executable type metadata for later diff operation with packages
tmp-executable-files.txt            - All files with +x attributes (executables)
tmp-types.txt                       - tmp file for Find types of executable(script\|ELF\|executable)
var-www-dir-timeline                - Timeline of all files in /var/www/*
whoandwhat.txt                  - w command output. Who is logged on and what they are doing.
who.txt                         - List of users who are currently logged in
wtmp-lastlog.txt                - wtmp last log
varlogs                         - All contents of /var/log
viminfo                         - All viminfo files... Can contain vi historic commands
```

## Disclaimer

Note that the script will likely alter artefacts on endpoints. Care should be taken when using the script. This is not meant to take forensically sound disk images of the remote endpoints.


## Tested OSs

- Ubuntu 16.4
- Centos
- Mint
- Solaris 11.4
