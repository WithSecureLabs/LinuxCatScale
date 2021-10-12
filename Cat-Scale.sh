#!/bin/bash
#
# Cat-Scale Linux Collection Script
# Author: Mehmet Mert Surmeli
# Contributers: John Rogers, Joani Green, Nikolaos Pavlidis
# Version: 1.2
# Release Date: 2021-09-03
#
# Latest public release available at https://github.com/FSecureLABS/LinuxCatScale
#
# Instructions:
# 1. Ensure the script is executable, run "chmod +x <script_name>"
# 2. Run with Sudo privileges, "sudo ./<script_name>"
#
# What this script does:
#  - Collects volatile data such as running processes and network connections
#  - Collects system information and configuration
#  - Enumerates and collects persistence data (programs that run either routinely or when the system starts)
#  - Collects log data from /var/log (contains security and application logs)
#  - Creates and records SHA1 cryptographic hashes of binary files
# The script does this by executing local binaries on your system. It does not install or drop any binaries on your system or change configurations. 
# This script may alter forensic artefacts, it is not recommended where evidence preservation is important.
#

######################################################################################################
############################################ Global Variables ########################################
######################################################################################################

# Force hostname format
if hostname -s &>/dev/null; then
	SHORTNAME=$(hostname -s)
else
	SHORTNAME=$(hostname)
fi

# Force date format
DTG=$(date +"%Y%m%d-%H%M")
# Outfile name
OUTFILE=$SHORTNAME-$DTG

#Define Global Variables
oscheck=$(find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat 2>/dev/null | tr [:upper:] [:lower:])
osid=''
uname=''
OUTPUT=.

######################################################################################################
########################################### FUNCTIONS ################################################
######################################################################################################

#
# Check for root/sudo privileges
#
amiroot(){ #Production
ROOT_UID="0"
if [ "$UID" -ne "$ROOT_UID" ] ; then
 clear
 echo " "
 echo " ***************************************************************"
 echo "  ERROR: You must have root/sudo privileges to run this script!"
 echo " "
 echo "  Hint: try 'sudo ./<script_name>'"
 echo " "
 echo " ***************************************************************"
 echo " "
 exit
fi
}

#
# Perform precollection actions.
#
starttheshow(){ #Production
	# Prompt for output path 
	clear
	echo " **********************************************************************************************"
	echo " *  ██████╗ █████╗ ████████╗      ███████╗ ██████╗ █████╗ ██╗     ███████╗         ^~^        *"
	echo " * ██╔════╝██╔══██╗╚══██╔══╝      ██╔════╝██╔════╝██╔══██╗██║     ██╔════╝        ('Y')       *"
	echo " * ██║     ███████║   ██║   █████╗███████╗██║     ███████║██║     █████╗        _\/   \ _     *"
	echo " * ██║     ██╔══██║   ██║   ╚════╝╚════██║██║     ██╔══██║██║     ██╔══╝       / (\|||/) \    *"
	echo " * ╚██████╗██║  ██║   ██║         ███████║╚██████╗██║  ██║███████╗███████╗    /____▄▄▄____\   *"
	echo " *  ╚═════╝╚═╝  ╚═╝   ╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝    =============   *"
	echo " *                                  Linux Collection                                          *"
	echo " **********************************************************************************************"
    
	# Exit if catscale_out folder exit. 
	if [ -d $OUTPUT/catscale_out ]; then
	 echo " "
	 echo " ******************************************************"
	 echo "  ERROR: Output path directory(catscale_out) already exists! " 
	 echo " ******************************************************"
	 echo " "
	 exit
	fi

	# Create output directory if does not exist and chmod it
	mkdir $OUTPUT/catscale_out
	chmod 600 $OUTPUT/catscale_out
	mkdir $OUTPUT/catscale_out/Process_and_Network
	mkdir $OUTPUT/catscale_out/Logs
	mkdir $OUTPUT/catscale_out/System_Info
	mkdir $OUTPUT/catscale_out/Persistence
	mkdir $OUTPUT/catscale_out/User_Files
	mkdir $OUTPUT/catscale_out/Misc
	mkdir $OUTPUT/catscale_out/Docker
	mkdir $OUTPUT/catscale_out/Podman
	mkdir $OUTPUT/catscale_out/Virsh
	# Print OS info into error log
	echo " "
	echo "Running Collection Scripts "
	echo " "
	echo oscheck: $oscheck > $OUTPUT/catscale_out/$OUTFILE-console-error-log.txt
	echo Date : $(date) >> $OUTPUT/catscale_out/$OUTFILE-console-error-log.txt
	echo "================================ Console Errors ================================" >> $OUTPUT/catscale_out/$OUTFILE-console-error-log.txt
	echo Date : $(date) > $OUTPUT/catscale_out/System_Info/$OUTFILE-host-date-timezone.txt 
 }
 
#
# Collect all hidden files in User directory. Non-recursive.
# includes .bash_history .bashrc .viminfo .bash_profile .profile
#
get_hidden_home_files(){ #Production

 grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f6 -d ':' | xargs -I {} find {} ! -path {} -prune -type f -name .\* -print0 | xargs -0 tar -czvf $OUTPUT/catscale_out/User_Files/hidden-user-home-dir.tar.gz  > $OUTPUT/catscale_out/User_Files/hidden-user-home-dir-list.txt

}

#
# Get root directory find timeline functions
#
get_find_timeline(){ #Production
	
	{
		echo "Inode,Hard link Count,Full Path,Last Access,Last Modification,Last Status Change,File Creation,User,Group,File Permissions,File Size(bytes)"
		find / -xdev -print0 | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 2>/dev/null
		find /dev/shm -print0 | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 2>/dev/null
	}> $OUTPUT/catscale_out/Misc/$OUTFILE-full-timeline.csv
	
}

#
# Get process information functions
#
get_procinfo_GNU(){ #Production
	
	echo "      Collecting Active Process..."
	PS_FORMAT=user,pid,ppid,vsz,rss,tname,stat,stime,time,args
	if ps axwwSo $PS_FORMAT &> /dev/null; then
		ps axwwSo $PS_FORMAT > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-axwwSo.txt
	elif ps auxSww &> /dev/null; then
		ps auxSww > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-auxSww.txt
	elif ps auxww &> /dev/null; then
		ps auxww > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-auxww.txt
	elif ps -eF &> /dev/null; then
		ps -eF > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-eF.txt
	elif ps -ef &> /dev/null; then
		ps -ef > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-ef.txt
	else
		ps -e > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-e.txt
	fi
	

	echo "      Getting the proc/*/status..."
	find /proc -maxdepth 2 -wholename '/proc/[0-9]*/status' | xargs cat  >> $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-process-details.txt

	echo "      Getting the process hashes..."
	find -L /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 sha1sum 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processhashes.txt	
	
	echo "      Getting the process symbolic links..."
	find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-process-exe-links.txt	
    
    echo "      Getting the process map_files hashes..."
	find -L /proc/[0-9]*/map_files -type f -print0 2>/dev/null | xargs -0 sha1sum 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-process-map_files-link-hashes.txt
    
    echo "      Getting the process map_files links..."
	find /proc/[0-9]*/map_files -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-process-map_files-links.txt
    
	echo "      Getting the process fd links..."
	find /proc/[0-9]*/fd -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-process-fd-links.txt
	
	echo "      Getting the process cmdline..."
	find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-process-cmdline.txt

	if which lsof &>/dev/null; then

		lsof +c0 -M -R -V -w -n -P -e /run/user/1000/gvfs > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-lsof-list-open-files.txt

  fi

}
get_procinfo_Solaris(){ #Production
	
	#more efficient way. Keeps in memory? more noisy?
	#if output=$(ps -ef 2>/dev/null); then printf "%s\n" "$output" ; else echo no; fi
	echo "      Collecting Active Process ..."
	if ps -ef &> /dev/null; then
		ps -ef > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-ef.txt
	else
		ps -e > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processes-e.txt
	fi
	
	echo "      Getting the process hashes..."
	find /proc/[0-9]*/object -name a.out | xargs sha1sum 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-processhashes.txt
	
	echo "      Getting the process cmdline..."
	find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-process-cmdline.txt
	
	if which lsof &>/dev/null; then
		lsof -n -P -e /run/user/1000/gvfs > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-lsof-list-open-files.txt
	fi
}


#
# Get network information functions
# 
#
get_netinfo_GNU(){ #Production
	
	#Get all network connections
	echo "      Collecting Active Network Connections..."
	if ss -anepo &>/dev/null; then
		ss -anepo > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-ss-anepo.txt

	elif netstat -pvWanoee &>/dev/null; then
		netstat -pvWanoee > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-netstat-pvWanoee.txt

	elif netstat -pvTanoee &>/dev/null; then
		netstat -pvTanoee > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-netstat-pvTanoee.txt

	else
		netstat -antup > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-netstat-antup.txt
		netstat -an > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-netstat-an.txt

	fi
	
	#Get ip and interface config
	echo "      Collecting IP and Interface Config..."
	if ip a &>/dev/null; then
		ip a > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-ip-a.txt
	else 
		ifconfig -a > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-ifconfig.txt
	fi
	
	#Get routing table
	echo "      Collecting Routing Table..."
	if ip route &>/dev/null; then
		ip route > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-routetable.txt
	else
		netstat -rn > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-routetable.txt
	fi
	
	#Get iptables. Firewall rules.
	echo "      Collecting IPtables..."

	iptables -L -n -v --line-numbers > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-iptables-numerical.txt
  
	iptables -L > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-iptables.txt

	

	#Get SeLinux Verbose information
	if sestatus &>/dev/null; then
		echo "      Collecting SELinux status..."
		sestatus -v > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-selinux.txt
		echo "      Collecting SELinux booleans..."
		getsebool -a > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-getsebool.txt
	fi
	
	
}
get_netinfo_Solaris(){ #Production
	
	#Get network connections
	echo "      Collecting Active Network Connections..."
	netstat -an > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-netstat-an.txt

	#Get ip and interface config
	echo "      Collecting IP and Interface Config..."
	ifconfig -a > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-ifconfig.txt
	
	#Get ipf table. Firewall rules. Might need further testing and optimization 
	if which ipfstat &>/dev/null; then
		echo "      Collecting ipf tables..."
		ipfstat -ion > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-ipftables.txt
	fi

	#Get routing table
	echo "      Collecting Routing Table..."
	netstat -rn > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-routetable.txt
	
	#Get SeLinux Verbose information
	if sestatus &>/dev/null; then
		echo "      Collecting SELinux status..."
		sestatus -v > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-selinux.txt
		echo "      Collecting SELinux booleans..."
		getsebool -a > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-getsebool.txt
	fi

}


#
# Get config files functions
#
get_config_GNU(){ #Production
	
    # Get key host files
	files="( -iname yum* -o -iname apt* -o -iname hosts* -o -iname passwd \
	-o -iname sudoers* -o -iname cron* -o -iname ssh* -o -iname rc* -o -iname systemd* -o -iname anacron  \
	-o -iname inittab -o -iname init.d -o -iname profile* -o -iname bash* )"
    find /etc/ -type f,d $files -print0 | xargs -0 tar -czvf $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-key-files.tar.gz 2>/dev/null > $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-key-files-list.txt
    
    # Get files that were modified in the last 90 days, collect all files, including symbolic links
    find /etc/ -type f -mtime -90 -print0 | xargs -0 tar -czvf $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-modified-files.tar.gz --dereference --hard-dereference 2>/dev/null > $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-modified-files-list.txt
	
}

get_config_Solaris(){ #Production
	
    # Get key host files
	files="( ( -iname yum* -o -iname apt* -o -iname hosts* -o -iname passwd \
	-o -iname sudoers* -o -iname cron* -o -iname ssh* -o -iname rc* -o -iname systemd* -o -iname anacron  \
	-o -iname inittab -o -iname init.d -o -iname profile* -o -iname bash* ) -a ( -type f -o -type d ) )"
	find /etc/ $files -print0 | xargs -0 tar -czvf $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-key-files.tar.gz 2>/dev/null > $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-key-files-list.txt 
    
    # Get files that were modified in the last 90 days, collect all files, including symbolic links
    find /etc/ -mtime -90 -print0 | xargs -0 tar -czvf $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-modified-files.tar.gz 2>/dev/null > $OUTPUT/catscale_out/System_Info/$OUTFILE-etc-modified-files-list.txt 
	
}

#
# Get Logs functions
#
get_logs_GNU(){ #Production

	echo "      Collecting logged in users..."
	who -a > $OUTPUT/catscale_out/Logs/$OUTFILE-who.txt
	
	echo "      Collecting 'w'..."
	w > $OUTPUT/catscale_out/Logs/$OUTFILE-whoandwhat.txt

	echo "      Collecting bad logins(btmp)..."
	find /var/log -maxdepth 1 -type f -name "btmp*" -exec last -Faiwx -f {} \; > $OUTPUT/catscale_out/Logs/$OUTFILE-last-btmp.txt
	
	echo "      Collecting Active Logon information(utmp)..."
	find / -maxdepth 2 -type f -name "utmp*" -exec last -Faiwx -f {} \; > $OUTPUT/catscale_out/Logs/$OUTFILE-last-utmp.txt
	find / -maxdepth 2 -type f -name "utmp*" -exec utmpdump {} \; > $OUTPUT/catscale_out/Logs/$OUTFILE-last-utmpdump.txt
	
	echo "      Collecting Historic Logon information(wtmp)..."
	find /var/log -maxdepth 1 -type f -name "wtmp*" -exec last -Faiwx -f {} \; > $OUTPUT/catscale_out/Logs/$OUTFILE-last-wtmp.txt
	
	echo "      Collecting lastlog..."
	lastlog > $OUTPUT/catscale_out/Logs/$OUTFILE-lastlog.txt

	echo "      Checking passwd integrity"
	pwck -r > $OUTPUT/catscale_out/Logs/$OUTFILE-passwd-check.txt

	#Collect all files in in /var/log folder.
	echo "      Collecting /var/log/ folder..."
	tar -czvf $OUTPUT/catscale_out/Logs/$OUTFILE-var-log.tar.gz --dereference --hard-dereference --sparse /var/log > $OUTPUT/catscale_out/Logs/$OUTFILE-var-log-list.txt

	#Collect all files in in /var/crash folder.
	echo "      Collecting /var/crash/ folder..."
    tar -czvf $OUTPUT/catscale_out/Logs/$OUTFILE-var-crash.tar.gz --dereference --hard-dereference --sparse /var/crash > $OUTPUT/catscale_out/Logs/$OUTFILE-var-crash-list.txt
	
}
get_logs_Solaris(){ #Production

	echo "      Collecting logged in users..."
	who -a > $OUTPUT/catscale_out/Logs/$OUTFILE-who.txt
	
	echo "      Collecting 'w'..."
	w > $OUTPUT/catscale_out/Logs/$OUTFILE-whoandwhat.txt

	echo "      Collecting bad logins(btmp)..."
	find /var/adm -type f -name "btmp*" -exec last -f {} \; > $OUTPUT/catscale_out/Logs/$OUTFILE-last-btmpx.txt
	
	echo "      Collecting Historic Logon information(wtmp)..."
	find /var/adm -type f -name "wtmp*" -exec last -f {} \; > $OUTPUT/catscale_out/Logs/$OUTFILE-last-wtmpx.txt

	#Collect all files in in /var/log folder.
	echo "      Collecting /var/log/ folder..."
	find /var/log -type f -print0 | xargs -0 tar -czfv $OUTPUT/catscale_out/Logs/$OUTFILE-var-log.tar.gz > $OUTPUT/catscale_out/Logs/$OUTFILE-var-log-list.txt
	
	#Collect all files in in /var/adm folder.
	echo "      Collecting /var/adm/ folder..."
	find /var/adm -type f -print0 | xargs -0 tar -czfv $OUTPUT/catscale_out/Logs/$OUTFILE-var-adm.tar.gz  > $OUTPUT/catscale_out/Logs/$OUTFILE-var-adm-list.txt

	#Collect all files in in /var/crash folder.
	echo "      Collecting /var/crash/ folder..."
	find /var/crash -type f -print0 | xargs -0 tar -czfv $OUTPUT/catscale_out/Logs/$OUTFILE-var-crash.tar.gz  > $OUTPUT/catscale_out/Logs/$OUTFILE-var-crash-list.txt

}


#
# Get User configs
#
get_sshkeynhosts(){ #Production
	
	echo "      Collecting .ssh folder..."
	find / -xdev -type d -name .ssh -print0 | xargs -0 tar -czvf $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-ssh-folders.tar.gz > $OUTPUT/catscale_out/Process_and_Network/$OUTFILE-ssh-folders-list.txt

}


#
# Get system information
#
get_systeminfo_GNU(){ #Production

	echo "      Collecting Memory info..."
	cat /proc/meminfo > $OUTPUT/catscale_out/System_Info/$OUTFILE-meminfo.txt
	
	echo "      Collecting CPU info..."
	cat /proc/cpuinfo > $OUTPUT/catscale_out/System_Info/$OUTFILE-cpuinfo.txt
	
	echo "      Collecting df..."
	df > $OUTPUT/catscale_out/System_Info/$OUTFILE-df.txt
	
	echo "      Collecting mount..."
	mount > $OUTPUT/catscale_out/System_Info/$OUTFILE-mount.txt
	
	echo "      Collecting attached USB device info..."
	lsusb -v > $OUTPUT/catscale_out/System_Info/$OUTFILE-lsusb.txt

	echo "      Collecting kernel release..."	
	find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat 2>/dev/null > $OUTPUT/catscale_out/System_Info/$OUTFILE-release.txt
	echo -n "KERNELVERSION(uname -r)=" >> $OUTPUT/catscale_out/System_Info/$OUTFILE-release.txt
	uname -r >> $OUTPUT/catscale_out/System_Info/$OUTFILE-release.txt

	echo "      Collecting lsmod..."
	lsmod > $OUTPUT/catscale_out/System_Info/$OUTFILE-lsmod.txt
	
	echo "      Collecting modinfo..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do echo -e "\nModule: $i"; modinfo $i ; done > $OUTPUT/catscale_out/System_Info/$OUTFILE-modinfo.txt

	echo "      Collecting loaded modules..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do modinfo $i | grep "filename:" | awk '{print $2}' | xargs -I{} sha1sum {} ; done > $OUTPUT/catscale_out/System_Info/$OUTFILE-module-sha1.txt
	
	echo "      Collecting proc/modules..."
	cat '/proc/modules' > $OUTPUT/catscale_out/System_Info/$OUTFILE-procmod.txt
	
	echo "      Collecting sudo config..."
	sudo -V > $OUTPUT/catscale_out/System_Info/$OUTFILE-sudo.txt

	echo "      Collecting dmesg..."
	dmesg -T > $OUTPUT/catscale_out/System_Info/$OUTFILE-dmesg.txt


}
get_systeminfo_Solaris(){ #Production

	echo "      Collecting Memory info..."
	vmstat -p > $OUTPUT/catscale_out/System_Info/$OUTFILE-meminfo.txt
	prstat -s size 1 1 > $OUTPUT/catscale_out/System_Info/$OUTFILE-ProcMemUsage.txt
	ipcs -a > $OUTPUT/catscale_out/System_Info/$OUTFILE-SharedMemAndSemaphores.txt
		
	echo "      Collecting CPU info..."
	prtdiag -v > $OUTPUT/catscale_out/System_Info/$OUTFILE-cpuinfo.txt
	psrinfo -v >> $OUTPUT/catscale_out/System_Info/$OUTFILE-cpuinfo.txt
	
	echo "      Collecting df..."
	df > $OUTPUT/catscale_out/System_Info/$OUTFILE-df.txt
	
	echo "      Collecting attached USB device info..."
	rmformat > $OUTPUT/catscale_out/System_Info/$OUTFILE-removeblemedia.txt
	
	echo "      Collecting kernel release..."		
	find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat 2>/dev/null > $OUTPUT/catscale_out/System_Info/$OUTFILE-release.txt

	echo "      Collecting loaded modules..."
	modinfo -ao namedesc,state,loadcnt,path > $OUTPUT/catscale_out/System_Info/$OUTFILE-modules.txt	
	
}

#
# Get Docker and Virtual machine info
#
get_docker_info(){ #Testing
	if docker --help &>/dev/null; then
		echo "      Collecting Docker info..."
		docker container ls --all --size > $OUTPUT/catscale_out/Docker/$OUTFILE-docker-container-ls-all-size.txt
		docker image ls --all > $OUTPUT/catscale_out/Docker/$OUTFILE-docker-image-ls-all.txt
		docker info > $OUTPUT/catscale_out/Docker/docker-info.txt
		docker container ps -all | sed 1d | cut -d" " -f 1 | while read line; do 
			docker container logs $line > $OUTPUT/catscale_out/Docker/$OUTFILE-docker-container-logs-$line.txt
		done 2>/dev/null
		docker container ps -all | sed 1d | cut -d" " -f 1 | while read line; do
		 	docker inspect $line > $OUTPUT/catscale_out/Docker/$OUTFILE-docker-inspect-$line.txt;
		done 2>/dev/null
		docker network ls | sed 1d | cut -d" " -f 1 | while read line; do 
			docker network inspect $line > $OUTPUT/catscale_out/Docker/$OUTFILE-docker-network-inspect-$line.txt
		done 2>/dev/null
		docker ps | sed 1d | cut -d" " -f 1 | while read line; do 		
			docker top $line > $OUTPUT/catscale_out/Docker/$OUTFILE-docker-top-$line.txt
		done 2>/dev/null
		docker version > $OUTPUT/catscale_out/Docker/$OUTFILE-docker-version.txt
	fi
	if podman --help &>/dev/null; then
		echo "      Collecting Podman info..."
		podman container ls --all --size > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-container-ls-all-size.txt
		podman image ls --all > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-image-ls-all.txt
		podman info > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-info.txt
		podman container ps -all | sed 1d | cut -d" " -f 1 | while read line; do
			podman container logs $line > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-container-logs-$line.txt
		done 2>/dev/null
		podman container ps -all | sed 1d | cut -d" " -f 1 | while read line; do
			podman inspect $line > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-inspect-$line.txt
		done 2>/dev/null
		podman network ls | sed 1d | cut -d" " -f 1 | while read line; do
			podman network inspect $line > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-network-inspect-$line.txt
		done 2>/dev/null
		podman ps | sed 1d | cut -d" " -f 1 | while read line; do 
			podman top $line > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-top-$line.txt
		done 2>/dev/null
		podman version > $OUTPUT/catscale_out/Podman/$OUTFILE-podman-version.txt
	fi
	if virsh --help &>/dev/null; then
		echo "      Collecting Virsh info..."
		virsh list --all > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-list-all.txt
		virsh list --name | while read line; do 
			virsh domifaddr $line > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-domifaddr-$line.txt
		done 2>/dev/null
		virsh list --name | while read line; do 
			virsh dominfo $line > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-dominfo-$line.txt
		done 2>/dev/null
		virsh list --name | while read line; do 
			virsh dommemstat $line > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-dommemstat-$line.txt
		done 2> /dev/null
		virsh list --name | while read line; do 
			virsh snapshot-list $line > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-snapshot-list-$line.txt
		done 2>/dev/null
		virsh list --name | while read line; do 
			virsh vcpuinfo $line > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-vcpuinfo-$line.txt
		done 2>/dev/null
		virsh net-list --all > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-net-list-all.txt
		virsh net-list --all --name | while read line; do 
			virsh net-info $line > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-net-info-$line.txt
		done 2>/dev/null
		virsh net-list --all --name | while read line; do 
			virsh net-dhcp-leases $line > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-net-dhcp-leases-$line.txt
		done 2>/dev/null
		virsh nodeinfo > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-nodeinfo.txt
		virsh pool-list --all > $OUTPUT/catscale_out/Virsh/$OUTFILE-virsh-pool-list-all.txt
		virt-top -n 1 > $OUTPUT/catscale_out/Virsh/$OUTFILE-virt-top-n-1.txt
	fi
}

#
# Get installed pacakge information
#
get_packageinfo_GNU(){ #Production

	echo "      Collecting installed package info..."
	if dpkg --help &>/dev/null; then
		dpkg --list > $OUTPUT/catscale_out/System_Info/$OUTFILE-deb-packages.txt
	else 
		rpm -qa > $OUTPUT/catscale_out/System_Info/$OUTFILE-rpm-packages.txt
	fi
	
}
get_packageinfo_Solaris(){ #Production

	echo "      Collecting installed package info..."
	pkginfo > $OUTPUT/catscale_out/System_Info/$OUTFILE-solaris-packages.txt
	
}

#
# Persistence Checks functions
#
get_startup_files_GNU(){ #Production

	echo "      Collecting service status all..."
	echo "This file might be empty as Latest versions of Red Hat, Fedora and Centos do not use service command. If this is empty please review systemctl file. " > $OUTPUT/catscale_out/Persistence/$OUTFILE-service_status.txt
	service --status-all >> $OUTPUT/catscale_out/Persistence/$OUTFILE-service_status.txt
	systemctl --all --type=service > $OUTPUT/catscale_out/Persistence/$OUTFILE-systemctl_service_status.txt
	
	echo "      Collecting status for all installed unit files..."
	systemctl list-unit-files >> $OUTPUT/catscale_out/Persistence/$OUTFILE-systemctl_all.txt

	echo "      Collecting systemd..." 
	find /etc/systemd/ -name "*.service" -print0 | xargs -0 cat > $OUTPUT/catscale_out/Persistence/$OUTFILE-persistence-systemdlist.txt

}
get_startup_files_Solaris(){ #Production

	echo "      Collecting service status all..."
	svcs -a > $OUTPUT/catscale_out/Persistence/$OUTFILE-service_status.txt
	
}


#
# Cron files collection functions
#
get_cron_GNU(){ #Production

	# If archive is empty there were no files in var/spool/cron/crontabs directory
	tar -czvf $OUTPUT/catscale_out/Persistence/$OUTFILE-cron-folder.tar.gz /var/spool/cron > $OUTPUT/catscale_out/Persistence/$OUTFILE-cron-folder-list.txt
	
	for user in $(grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f1 -d ':'); 
	do 
		echo $user 
		crontab -u $user -l 
		echo "ENDOFUSERCRON"
	done &> $OUTPUT/catscale_out/Persistence/$OUTFILE-cron-tab-list.txt

}
get_cron_Solaris(){ #Production

	# If archive is empty there were no files in var/spool/cron/crontabs directory
	tar -czvf $OUTPUT/catscale_out/Persistence/$OUTFILE-cron-folder.tar.gz /var/spool/cron > $OUTPUT/catscale_out/Persistence/$OUTFILE-cron-folder-list.txt
	
	for user in $(grep "/bash" /etc/passwd | cut -f1 -d ':'); 
	do 
		echo $user
		crontab -l $user 2>/dev/null
	done &> $OUTPUT/catscale_out/Persistence/$OUTFILE-cron-tab-list.txt

}




#
# Find all files with execution permissions. 
#
get_executables(){ #Production

    find / -xdev -type f -perm -o+rx -print0 | xargs -0 sha1sum > $OUTPUT/catscale_out/Misc/$OUTFILE-exec-perm-files.txt

}

#
# Get suspicious information functions
#
get_suspicios_data(){ #Production

	#Find files in dev dir directory. Not common. Might be empty if none found
	find /dev/ -type f -print0 | xargs -0 file 2>/dev/null > $OUTPUT/catscale_out/Misc/$OUTFILE-dev-dir-files.txt
	#If no found there will be single entry with d41d8cd98f00b204e9800998ecf8427e - 
	find /dev/ -type f -print0 | xargs -0 sha1sum > $OUTPUT/catscale_out/Misc/$OUTFILE-dev-dir-files-hashes.txt

	#Find potential privilege escalation binaries/modifications (all Setuid Setguid binaries)
	find / -xdev -type f \( -perm -04000 -o -perm -02000 \) > $OUTPUT/catscale_out/Misc/$OUTFILE-Setuid-Setguid-tools.txt
}

#
# Find all files with .jsp, .asp, .aspx, .php extentions. Hash them and capture last 100 lines. For Solaris it simply gzips these files. 
# 
get_pot_webshell(){ #Production
    
    find / -xdev -type f \( -iname '*.jsp' -o -iname '*.asp' -o -iname '*.php' -o -iname '*.aspx' \) 2>/dev/null -print0 | xargs -0 sha1sum > $OUTPUT/catscale_out/Misc/$OUTFILE-pot-webshell-hashes.txt
    
    find / -xdev -type f \( -iname '*.jsp' -o -iname '*.asp' -o -iname '*.php' -o -iname '*.aspx' \) 2>/dev/null -print0 | xargs -0 head -1000 > $OUTPUT/catscale_out/Misc/$OUTFILE-pot-webshell-first-1000.txt
    
}
	
# 
# Artefact packaging and clean up
# 
end_colletion(){ #Production

	# Archive/Compress files
	echo " "
	echo " Creating catscale_$OUTFILE.tar.gz "
	tar -czf $OUTPUT/catscale_$OUTFILE.tar.gz $OUTPUT/catscale_out
	
	# Clean-up catscale_out directory if the tar exists
	if [ -f $OUTPUT/catscale_$OUTFILE.tar.gz ]; then
	 echo " "
	 echo " Cleaning up!..."
	 rm -r $OUTPUT/catscale_out
	fi
	
	# Check if clean-up has been successful
	if [ ! -d $OUTPUT/catscale_out ]; then
	 echo " Clean-up Successful!"
	fi
	if [ -d $OUTPUT/catscale_out ]; then
	 echo " "
	 echo " WARNING Clean-up has not been successful please manually remove;"
	 echo $OUTPUT/catscale_out
	fi
	
	# SHA1 the tar
	 echo " "
	 echo " *************************************************************"
	 echo "  Collection of triage data complete! "
	 echo "  Please submit the following file and SHA1 hash for analysis."
	 echo " *************************************************************"
	 echo " "
	sha1sum $OUTPUT/catscale_$OUTFILE.tar.gz 
	 echo " "
}


#####################################################################################################
############################################ Main Execution  ########################################
#####################################################################################################

amiroot
starttheshow

case $oscheck in
	*ubuntu*|*debian*)
		#Ubuntu/Debian
		{
	
			echo "Ubuntu\Debian Detected. Collecting;"
			echo " - Home directory hidden files..."
			get_hidden_home_files
			echo " - Process info..."
			get_procinfo_GNU
			echo " - Network info..."
			get_netinfo_GNU
			echo " - Logs..."
			get_logs_GNU
			echo " - System info..."
			get_systeminfo_GNU
			echo " - Installed Packages..."
			get_packageinfo_GNU
			echo " - Configuration Files..." 
			get_config_GNU
			echo " - File timeline..."
			get_find_timeline
			echo " - .ssh folder..."
			get_sshkeynhosts
			echo " - Boot/Login Scripts..."
			get_startup_files_GNU
			echo " - Crontabs..."
			get_cron_GNU
			echo " - Getting all executable file hashes..."
			get_executables
			echo " - Looking for suspicious files..."
			get_suspicios_data
			echo " - Hashing potential webshells..."
			get_pot_webshell
			
			
		} 2>> $OUTPUT/catscale_out/$OUTFILE-console-error-log.txt
		;;
	*"red hat"*|*rhel*|*fedora*|*centos*)
		#Red Hat\Centos\Fedora
		{
			
			echo "Red Hat\Centos\Fedora Detected. Collecting;"
			echo " - Home directory hidden files..."
			get_hidden_home_files
			echo " - Process info.."
			get_procinfo_GNU
			echo " - Network info..."
			get_netinfo_GNU
			echo " - Logs..."
			get_logs_GNU
			echo " - System info..."
			get_systeminfo_GNU
			echo " - Docker and Virtual Machine info..."
			get_docker_info
			echo " - Installed Packages..."
			get_packageinfo_GNU
			echo " - Configuration Files..." 
			get_config_GNU
			echo " - File timeline..."
			get_find_timeline
			echo " - .ssh folder..."
			get_sshkeynhosts
			echo " - Boot/Login Scripts..."
			get_startup_files_GNU
			echo " - Crontabs..."
			get_cron_GNU
			echo " - Getting all executable file hashes..."
			get_executables
			echo " - Looking for suspicious files..."
			get_suspicios_data
			echo " - Hashing potential webshells..."
			get_pot_webshell
			
		} 2>> $OUTPUT/catscale_out/$OUTFILE-console-error-log.txt
		;;
	*sunos*|*solaris*)
		#SunOS/Solaris
		{
			
			echo "Sunos\Solaris Detected. Collecting;"
			echo " - Home directory hidden files..."
			get_hidden_home_files
			echo " - Process info.."
			get_procinfo_Solaris
			echo " - Network info..."
			get_netinfo_Solaris
			echo " - Logs..."
			get_logs_Solaris
			echo " - System info..."
			get_systeminfo_Solaris
			echo " - Docker and Virtual Machine info..."
			get_docker_info
			echo " - Installed Packages..."
			get_packageinfo_Solaris
			echo " - Configuration Files..." 
			get_config_Solaris
			echo " - File timeline..."
			get_find_timeline
			echo " - .ssh folder..."
			get_sshkeynhosts
			echo " - Boot/Login Scripts..."
			get_startup_files_Solaris
			echo " - Crontabs..."
			get_cron_Solaris
			echo " - Getting all executable file hashes..."
			get_executables
			echo " - Looking for suspicious files..."
			get_suspicios_data
			echo " - Hashing potential webshells..."
			get_pot_webshell
			
		} 2>> $OUTPUT/catscale_out/$OUTFILE-console-error-log.txt
		;;
	*)
		#Incompatible Distribution
        {
			echo "Incompatible Distribution Detected. Using GNU methods and Hoping for the Best"
			echo " - Home directory hidden files..."
			get_hidden_home_files
			echo " - Process info.."
			get_procinfo_GNU
			echo " - Network info..."
			get_netinfo_GNU
			echo " - Logs..."
			get_logs_GNU
			echo " - System info..."
			get_systeminfo_GNU
			echo " - Docker and Virtual Machine info..."
			get_docker_info
			echo " - Installed Packages..."
			get_packageinfo_GNU
			echo " - Configuration Files..." 
			get_config_GNU
			echo " - File timeline..."
			get_find_timeline
			echo " - .ssh folder..."
			get_sshkeynhosts
			echo " - Boot/Login Scripts..."
			get_startup_files_GNU
			echo " - Crontabs..."
			get_cron_GNU
			echo " - Getting all executable file hashes..."
			get_executables
			echo " - Looking for suspicious files..."
			get_suspicios_data
			echo " - Hashing potential webshells..."
			get_pot_webshell
			
		} 2>> $OUTPUT/catscale_out/$OUTFILE-console-error-log.txt
        ;;
		
esac

end_colletion
exit
