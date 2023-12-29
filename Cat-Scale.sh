#!/bin/bash
#
# Cat-Scale Linux Collection Script
# Version: 1.3.1
# Release Date: 2021-11-30
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
# Check to see if options were passed in via CLI
function usage {
cat << EOF

Usage: sudo $0 [ -d OUTDIR ] [ -f OUTFILE ] [ -o OUTROOT ] [ -p OUTFILE_PREFIX ]

 -d	OUTDIR, Optional, Directory where output will be staged while running CatScale. Overwrites default, which is "catscale_out" 
 -f	OUTFILE, Optional, Name of resultant archive file created by CatScale (.tar.gz will be appended by the script). Overwrites default, which has the format of "catscale_<Hostname>-<DateAndTime>"
 -o	OUTROOT, Optional, Root directory/filesystem for output to be saved. Overwrites default, which is set to current directory script is running from, $(pwd). 
 -p	OUTFILE_PREFIX, Optional, Prefix to use for archive file. Overwrites default, which is "catscale_"

EOF
}

while getopts "d:f:o:p:h" OPTION
do
    case $OPTION in
        h)
            usage
            exit 0
            ;;
        d)
            OUTDIR=$OPTARG
            ;;
        f)
            OUTFILE=$OPTARG
            ;;
        o)
            OUTROOT=$OPTARG
            ;;
        p)
            OUTFILE_PREFIX=$OPTARG
            ;;
        *)
            usage
            exit 0
            ;;
    esac
done

# Force hostname format
if hostname -s &>/dev/null; then
	SHORTNAME=$(hostname -s)
else
	SHORTNAME=$(hostname)
fi

# Force date format
DTG=$(date +"%Y%m%d-%H%M")
# Outfile prefix
OUTFILE_PREFIX=${OUTFILE_PREFIX:-catscale_}
# Outfile name
OUTFILE=${OUTFILE:-$SHORTNAME-$DTG}
# Root dir/filesystem
OUTROOT=${OUTROOT:-.}
# Output directory
OUTDIR=${OUTDIR:-catscale_out}

#Define Global Variables
oscheck=$(find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat 2>/dev/null | tr [:upper:] [:lower:])
osid=''
uname=''

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
    
	# Exit if $OUTDIR folder exists.
	if [ -d $OUTROOT/$OUTDIR ]; then
	 echo " "
	 echo " ******************************************************"
	 echo "  ERROR: Output path directory($OUTDIR) already exists! "
	 echo " ******************************************************"
	 echo " "
	 exit
	fi

	# Create output directory if does not exist and chmod it
	mkdir $OUTROOT/$OUTDIR
	chmod 600 $OUTROOT/$OUTDIR
	mkdir $OUTROOT/$OUTDIR/Process_and_Network
	mkdir $OUTROOT/$OUTDIR/Logs
	mkdir $OUTROOT/$OUTDIR/System_Info
	mkdir $OUTROOT/$OUTDIR/Persistence
	mkdir $OUTROOT/$OUTDIR/User_Files
	mkdir $OUTROOT/$OUTDIR/Misc
	mkdir $OUTROOT/$OUTDIR/Docker
	mkdir $OUTROOT/$OUTDIR/Podman
	mkdir $OUTROOT/$OUTDIR/Virsh
	# Print OS info into error log
	echo " "
	echo "Running Collection Scripts "
	echo " "
	echo oscheck: $oscheck > $OUTROOT/$OUTDIR/$OUTFILE-console-error-log.txt
	echo Date : $(TZ=UTC date +'%c %:z') >> $OUTROOT/$OUTDIR/$OUTFILE-console-error-log.txt
	echo "================================ Console Errors ================================" >> $OUTROOT/$OUTDIR/$OUTFILE-console-error-log.txt
	echo Date : $(TZ=UTC date +'%c %:z') > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-host-date-timezone.txt
 }
 
#
# Collect all hidden files in User directory. Non-recursive.
# includes .bash_history .bashrc .viminfo .bash_profile .profile
#
get_hidden_home_files(){ #Production

 grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f6 -d ':' | xargs -I {} find {} ! -path {} -prune -type f -name .\* -print0 | xargs -0 tar -czvf $OUTROOT/$OUTDIR/User_Files/hidden-user-home-dir.tar.gz  > $OUTROOT/$OUTDIR/User_Files/hidden-user-home-dir-list.txt

}

#
# Get root directory find timeline functions
#
get_find_timeline(){ #Production
	
	{
		echo "Inode,Hard link Count,Full Path,Last Access,Last Modification,Last Status Change,File Creation,User,Group,File Permissions,File Size(bytes)"
		find / -xdev -print0 | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 2>/dev/null
		find /dev/shm -print0 | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 2>/dev/null
		find /tmp -print0 | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 2>/dev/null
	}> $OUTROOT/$OUTDIR/Misc/$OUTFILE-full-timeline.csv
	
}

#
# Get process information functions
#
get_procinfo_GNU(){ #Production
	
	echo "      Collecting Active Process..."
	PS_FORMAT=user,pid,ppid,vsz,rss,tname,stat,stime,time,args
	if ps axwwSo $PS_FORMAT &> /dev/null; then
		ps axwwSo $PS_FORMAT > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-axwwSo.txt
	elif ps auxSww &> /dev/null; then
		ps auxSww > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-auxSww.txt
	elif ps auxww &> /dev/null; then
		ps auxww > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-auxww.txt
	elif ps -eF &> /dev/null; then
		ps -eF > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-eF.txt
	elif ps -ef &> /dev/null; then
		ps -ef > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-ef.txt
	else
		ps -e > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-e.txt
	fi
	

	echo "      Getting the proc/*/status..."
	find /proc -maxdepth 2 -wholename '/proc/[0-9]*/status' | xargs cat  >> $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-details.txt

	echo "      Getting the process hashes..."
	find -L /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 sha1sum 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processhashes.txt
	
	echo "      Getting the process symbolic links..."
	find /proc/[0-9]*/exe -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-exe-links.txt
    
    echo "      Getting the process map_files hashes..."
	find -L /proc/[0-9]*/map_files -type f -print0 2>/dev/null | xargs -0 sha1sum 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-map_files-link-hashes.txt
    
    echo "      Getting the process map_files links..."
	find /proc/[0-9]*/map_files -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-map_files-links.txt
    
	echo "      Getting the process fd links..."
	find /proc/[0-9]*/fd -print0 2>/dev/null | xargs -0 ls -lh 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-fd-links.txt
	
	echo "      Getting the process cmdline..."
	find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-cmdline.txt

	echo "      Getting the process environment variables..."
	find /proc/[0-9]*/environ | xargs head 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-environment.txt

	if which lsof &>/dev/null; then

		lsof +c0 -M -R -V -w -n -P -e /run/user/1000/gvfs > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-lsof-list-open-files.txt

  fi

}
get_procinfo_Solaris(){ #Production
	
	#more efficient way. Keeps in memory? more noisy?
	#if output=$(ps -ef 2>/dev/null); then printf "%s\n" "$output" ; else echo no; fi
	echo "      Collecting Active Process ..."
	if ps -ef &> /dev/null; then
		ps -ef > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-ef.txt
	else
		ps -e > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processes-e.txt
	fi
	
	echo "      Getting the process hashes..."
	find /proc/[0-9]*/object -name a.out | xargs sha1sum 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-processhashes.txt
	
	echo "      Getting the process cmdline..."
	find /proc/[0-9]*/cmdline | xargs head 2>/dev/null > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-process-cmdline.txt
	
	if which lsof &>/dev/null; then
		lsof -n -P -e /run/user/1000/gvfs > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-lsof-list-open-files.txt
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
		ss -anepo > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-ss-anepo.txt

	elif netstat -pvWanoee &>/dev/null; then
		netstat -pvWanoee > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-netstat-pvWanoee.txt

	elif netstat -pvTanoee &>/dev/null; then
		netstat -pvTanoee > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-netstat-pvTanoee.txt

	else
		netstat -antup > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-netstat-antup.txt
		netstat -an > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-netstat-an.txt

	fi
	
	#Get ip and interface config
	echo "      Collecting IP and Interface Config..."
	if which ip &>/dev/null; then
		ip a > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-ip-a.txt
	else 
		ifconfig -a > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-ifconfig.txt
	fi
	
	#Get routing table
	echo "      Collecting Routing Table..."
	if ip --details route show table all &>/dev/null; then
		ip --details route show table all > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-routetable.txt
	else
		netstat -rn > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-routetable.txt
	fi
	
	#Get iptables. Firewall rules.
	echo "      Collecting IPtables..."

	iptables -L -n -v --line-numbers > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-iptables-numerical.txt
  
	iptables -L > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-iptables.txt

	

	#Get SeLinux Verbose information
	if which sestatus &>/dev/null; then
		echo "      Collecting SELinux status..."
		sestatus -v > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-selinux.txt
		echo "      Collecting SELinux booleans..."
		getsebool -a > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-getsebool.txt
	fi
	
	
}
get_netinfo_Solaris(){ #Production
	
	#Get network connections
	echo "      Collecting Active Network Connections..."
	netstat -an > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-netstat-an.txt

	#Get ip and interface config
	echo "      Collecting IP and Interface Config..."
	ifconfig -a > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-ifconfig.txt
	
	#Get ipf table. Firewall rules. Might need further testing and optimization 
	if which ipfstat &>/dev/null; then
		echo "      Collecting ipf tables..."
		ipfstat -ion > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-ipftables.txt
	fi

	#Get routing table
	echo "      Collecting Routing Table..."
	netstat -rn > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-routetable.txt
	
	#Get SeLinux Verbose information
	if which sestatus &>/dev/null; then
		echo "      Collecting SELinux status..."
		sestatus -v > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-selinux.txt
		echo "      Collecting SELinux booleans..."
		getsebool -a > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-getsebool.txt
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
    find /etc/ -type f,d $files -print0 | xargs -0 tar -czvf $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-key-files.tar.gz 2>/dev/null > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-key-files-list.txt
    
    # Get files that were modified in the last 90 days, collect all files, including symbolic links
    find /etc/ -type f -mtime -90 -print0 | xargs -0 tar -czvf $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-modified-files.tar.gz --dereference --hard-dereference 2>/dev/null > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-modified-files-list.txt
	
}

get_config_Solaris(){ #Production
	
    # Get key host files
	files="( ( -iname yum* -o -iname apt* -o -iname hosts* -o -iname passwd \
	-o -iname sudoers* -o -iname cron* -o -iname ssh* -o -iname rc* -o -iname systemd* -o -iname anacron  \
	-o -iname inittab -o -iname init.d -o -iname profile* -o -iname bash* ) -a ( -type f -o -type d ) )"
	find /etc/ $files -print0 | xargs -0 tar -czvf $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-key-files.tar.gz 2>/dev/null > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-key-files-list.txt
    
    # Get files that were modified in the last 90 days, collect all files, including symbolic links
    find /etc/ -mtime -90 -print0 | xargs -0 tar -czvf $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-modified-files.tar.gz 2>/dev/null > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-etc-modified-files-list.txt
	
}

#
# Get Logs functions
#
get_logs_GNU(){ #Production

	echo "      Collecting logged in users..."
	who -a > $OUTROOT/$OUTDIR/Logs/$OUTFILE-who.txt
	
	echo "      Collecting 'w'..."
	w > $OUTROOT/$OUTDIR/Logs/$OUTFILE-whoandwhat.txt

	echo "      Collecting bad logins(btmp)..."
	find /var/log -maxdepth 1 -type f -name "btmp*" -exec last -Faiwx -f {} \; > $OUTROOT/$OUTDIR/Logs/$OUTFILE-last-btmp.txt
	
	echo "      Collecting Active Logon information(utmp)..."
	find / -maxdepth 2 -type f -name "utmp*" -exec last -Faiwx -f {} \; > $OUTROOT/$OUTDIR/Logs/$OUTFILE-last-utmp.txt
	find / -maxdepth 2 -type f -name "utmp*" -exec utmpdump {} \; > $OUTROOT/$OUTDIR/Logs/$OUTFILE-last-utmpdump.txt
	
	echo "      Collecting Historic Logon information(wtmp)..."
	find /var/log -maxdepth 1 -type f -name "wtmp*" -exec last -Faiwx -f {} \; > $OUTROOT/$OUTDIR/Logs/$OUTFILE-last-wtmp.txt
	
	echo "      Collecting lastlog..."
	lastlog > $OUTROOT/$OUTDIR/Logs/$OUTFILE-lastlog.txt

	echo "      Checking passwd integrity"
	pwck -r > $OUTROOT/$OUTDIR/Logs/$OUTFILE-passwd-check.txt

	#Collect all files in in /var/log folder.
	echo "      Collecting /var/log/ folder..."
	tar -czvf $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-log.tar.gz --dereference --hard-dereference --sparse /var/log > $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-log-list.txt

	#Collect all files in in /var/crash folder.
	echo "      Collecting /var/crash/ folder..."
    tar -czvf $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-crash.tar.gz --dereference --hard-dereference --sparse /var/crash > $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-crash-list.txt
	
}
get_logs_Solaris(){ #Production

	echo "      Collecting logged in users..."
	who -a > $OUTROOT/$OUTDIR/Logs/$OUTFILE-who.txt
	
	echo "      Collecting 'w'..."
	w > $OUTROOT/$OUTDIR/Logs/$OUTFILE-whoandwhat.txt

	echo "      Collecting bad logins(btmp)..."
	find /var/adm -type f -name "btmp*" -exec last -f {} \; > $OUTROOT/$OUTDIR/Logs/$OUTFILE-last-btmpx.txt
	
	echo "      Collecting Historic Logon information(wtmp)..."
	find /var/adm -type f -name "wtmp*" -exec last -f {} \; > $OUTROOT/$OUTDIR/Logs/$OUTFILE-last-wtmpx.txt

	#Collect all files in in /var/log folder.
	echo "      Collecting /var/log/ folder..."
	find /var/log -type f -print0 | xargs -0 tar -czfv $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-log.tar.gz > $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-log-list.txt
	
	#Collect all files in in /var/adm folder.
	echo "      Collecting /var/adm/ folder..."
	find /var/adm -type f -print0 | xargs -0 tar -czfv $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-adm.tar.gz  > $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-adm-list.txt

	#Collect all files in in /var/crash folder.
	echo "      Collecting /var/crash/ folder..."
	find /var/crash -type f -print0 | xargs -0 tar -czfv $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-crash.tar.gz  > $OUTROOT/$OUTDIR/Logs/$OUTFILE-var-crash-list.txt

}


#
# Get User configs
#
get_sshkeynhosts(){ #Production
	
	echo "      Collecting .ssh folder..."
	find / -xdev -type d -name .ssh -print0 | xargs -0 tar -czvf $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-ssh-folders.tar.gz > $OUTROOT/$OUTDIR/Process_and_Network/$OUTFILE-ssh-folders-list.txt

}


#
# Get system information
#
get_systeminfo_GNU(){ #Production

	echo "      Collecting Memory info..."
	cat /proc/meminfo > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-meminfo.txt
	
	echo "      Collecting CPU info..."
	cat /proc/cpuinfo > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-cpuinfo.txt
	
	echo "      Collecting df..."
	df > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-df.txt
	
	echo "      Collecting mount..."
	mount > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-mount.txt
	
	echo "      Collecting attached USB device info..."
	lsusb -v > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-lsusb.txt

	echo "      Collecting kernel release..."	
	find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat 2>/dev/null > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-release.txt
	echo -n "KERNELVERSION(uname -r)=" >> $OUTROOT/$OUTDIR/System_Info/$OUTFILE-release.txt
	uname -r >> $OUTROOT/$OUTDIR/System_Info/$OUTFILE-release.txt

	echo "      Collecting lsmod..."
	lsmod > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-lsmod.txt
	
	echo "      Collecting modinfo..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do echo -e "\nModule: $i"; modinfo $i ; done > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-modinfo.txt

	echo "      Collecting loaded modules..."
	for i in `lsmod | awk '{print $1}' | sed '/Module/d'`; do modinfo $i | grep "filename:" | awk '{print $2}' | xargs -I{} sha1sum {} ; done > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-module-sha1.txt
	
	echo "      Collecting proc/modules..."
	cat '/proc/modules' > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-procmod.txt
	
	echo "      Collecting sudo config..."
	sudo -V > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-sudo.txt

	echo "      Collecting dmesg..."
	dmesg -T > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-dmesg.txt


}
get_systeminfo_Solaris(){ #Production

	echo "      Collecting Memory info..."
	vmstat -p > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-meminfo.txt
	prstat -s size 1 1 > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-ProcMemUsage.txt
	ipcs -a > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-SharedMemAndSemaphores.txt
		
	echo "      Collecting CPU info..."
	prtdiag -v > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-cpuinfo.txt
	psrinfo -v >> $OUTROOT/$OUTDIR/System_Info/$OUTFILE-cpuinfo.txt
	
	echo "      Collecting df..."
	df > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-df.txt
	
	echo "      Collecting attached USB device info..."
	rmformat > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-removeblemedia.txt
	
	echo "      Collecting kernel release..."		
	find /etc ! -path /etc -prune -name "*release*" -print0 | xargs -0 cat 2>/dev/null > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-release.txt

	echo "      Collecting loaded modules..."
	modinfo -ao namedesc,state,loadcnt,path > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-modules.txt
	
}

#
# Get Docker and Virtual machine info
#
get_docker_info(){ #Testing
	if which docker &>/dev/null; then
		echo "      Collecting Docker info..."
		docker container ls --all --size > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-container-ls-all-size.txt
		docker image ls --all > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-image-ls-all.txt
		docker info > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-info.txt
		docker container ps --all -q | while read line; do 
			docker inspect $line > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-inspect-$line.txt
			docker container top $line > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-top-$line.txt
			docker container logs $line > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-container-logs-$line.txt
			docker container port $line > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-container-port-$line.txt
			docker container diff $line > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-container-diff-$line.txt
		done 2>/dev/null
		docker network ls | sed 1d | cut -d" " -f 1 | while read line; do 
			docker network inspect $line > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-network-inspect-$line.txt
		done 2>/dev/null
		docker version > $OUTROOT/$OUTDIR/Docker/$OUTFILE-docker-version.txt
	fi
	if which podman &>/dev/null; then
		echo "      Collecting Podman info..."
		podman container ls --all --size > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-container-ls-all-size.txt
		podman image ls --all > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-image-ls-all.txt
		podman info > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-info.txt
		podman container ps --all -q | while read line; do
			podman inspect $line > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-inspect-$line.txt
			podman container top $line > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-top-$line.txt
			podman container logs $line > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-container-logs-$line.txt
			podman container port $line > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-container-port-$line.txt
			podman container diff $line > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-container-diff-$line.txt
		done 2>/dev/null
		podman network ls | sed 1d | cut -d" " -f 1 | while read line; do
			podman network inspect $line > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-network-inspect-$line.txt
		done 2>/dev/null
		podman version > $OUTROOT/$OUTDIR/Podman/$OUTFILE-podman-version.txt
	fi
	if which virsh &>/dev/null; then
		echo "      Collecting Virsh info..."
		virsh list --all > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-list-all.txt
		virsh list --name | while read line; do 
			virsh domifaddr $line > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-domifaddr-$line.txt
			virsh dominfo $line > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-dominfo-$line.txt
			virsh dommemstat $line > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-dommemstat-$line.txt
			virsh snapshot-list $line > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-snapshot-list-$line.txt
			virsh vcpuinfo $line > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-vcpuinfo-$line.txt
		done 2>/dev/null
		virsh net-list --all > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-net-list-all.txt
		virsh net-list --all --name | while read line; do 
			virsh net-info $line > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-net-info-$line.txt
			virsh net-dhcp-leases $line > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-net-dhcp-leases-$line.txt
		done 2>/dev/null
		virsh nodeinfo > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-nodeinfo.txt
		virsh pool-list --all > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virsh-pool-list-all.txt
		virt-top -n 1 > $OUTROOT/$OUTDIR/Virsh/$OUTFILE-virt-top-n-1.txt
	fi
}

#
# Get installed pacakge information
#
get_packageinfo_GNU(){ #Production

	echo "      Collecting installed package info..."
	if which dpkg &>/dev/null; then
		dpkg --list > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-deb-packages.txt
	elif which zypper &>/dev/null; then
		zypper search -si > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-zypper-packages.txt
	else 
		rpm -qa > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-rpm-packages.txt
	fi
	
}
get_packageinfo_Solaris(){ #Production

	echo "      Collecting installed package info..."
	pkginfo > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-solaris-packages.txt
	
}

#
# Verify installed pacakge information
#
vrfy_packageinfo_GNU(){ #Production

	echo "      Verifying installed package info..."
	if which dpkg &>/dev/null; then
		dpkg -V > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-deb-package-verify.txt
	else 
		rpm -qVa > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-rpm-package-verify.txt
	fi
	
}
vrfy_packageinfo_Solaris(){ #Production

	echo "      Verifying installed package info..."
	pkg verify -v > $OUTROOT/$OUTDIR/System_Info/$OUTFILE-solaris-package-verify.txt
	
}

#
# Persistence Checks functions
#
get_startup_files_GNU(){ #Production

	echo "      Collecting service status all..."
	echo "This file might be empty as Latest versions of Red Hat, Fedora and Centos do not use service command. If this is empty please review systemctl file. " > $OUTROOT/$OUTDIR/Persistence/$OUTFILE-service_status.txt
	service --status-all >> $OUTROOT/$OUTDIR/Persistence/$OUTFILE-service_status.txt
	systemctl --all --type=service > $OUTROOT/$OUTDIR/Persistence/$OUTFILE-systemctl_service_status.txt
	
	echo "      Collecting status for all installed unit files..."
	systemctl list-unit-files >> $OUTROOT/$OUTDIR/Persistence/$OUTFILE-systemctl_all.txt

	echo "      Collecting systemd..." 
	find /etc/systemd/ -name "*.service" -print0 | xargs -0 cat > $OUTROOT/$OUTDIR/Persistence/$OUTFILE-persistence-systemdlist.txt

}
get_startup_files_Solaris(){ #Production

	echo "      Collecting service status all..."
	svcs -a > $OUTROOT/$OUTDIR/Persistence/$OUTFILE-service_status.txt
	
}


#
# Cron files collection functions
#
get_cron_GNU(){ #Production

	# If archive is empty there were no files in var/spool/cron/crontabs directory
	tar -czvf $OUTROOT/$OUTDIR/Persistence/$OUTFILE-cron-folder.tar.gz /var/spool/cron > $OUTROOT/$OUTDIR/Persistence/$OUTFILE-cron-folder-list.txt
	
	for user in $(grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f1 -d ':'); 
	do 
		echo $user 
		crontab -u $user -l 
		echo "ENDOFUSERCRON"
	done &> $OUTROOT/$OUTDIR/Persistence/$OUTFILE-cron-tab-list.txt

}
get_cron_Solaris(){ #Production

	# If archive is empty there were no files in var/spool/cron/crontabs directory
	tar -czvf $OUTROOT/$OUTDIR/Persistence/$OUTFILE-cron-folder.tar.gz /var/spool/cron > $OUTROOT/$OUTDIR/Persistence/$OUTFILE-cron-folder-list.txt
	
	for user in $(grep "/bash" /etc/passwd | cut -f1 -d ':'); 
	do 
		echo $user
		crontab -l $user 2>/dev/null
	done &> $OUTROOT/$OUTDIR/Persistence/$OUTFILE-cron-tab-list.txt

}




#
# Find all files with execution permissions. 
#
get_executables(){ #Production

    find / -xdev -type f -perm -o+rx -print0 | xargs -0 sha1sum > $OUTROOT/$OUTDIR/Misc/$OUTFILE-exec-perm-files.txt

}

#
# Get suspicious information functions
#
get_suspicios_data(){ #Production

	#Find files in dev dir directory. Not common. Might be empty if none found
	find /dev/ -type f -print0 | xargs -0 file 2>/dev/null > $OUTROOT/$OUTDIR/Misc/$OUTFILE-dev-dir-files.txt
	#If no found there will be single entry with d41d8cd98f00b204e9800998ecf8427e - 
	find /dev/ -type f -print0 | xargs -0 sha1sum > $OUTROOT/$OUTDIR/Misc/$OUTFILE-dev-dir-files-hashes.txt

	#Find potential privilege escalation binaries/modifications (all Setuid Setguid binaries)
	find / -xdev -type f \( -perm -04000 -o -perm -02000 \) > $OUTROOT/$OUTDIR/Misc/$OUTFILE-Setuid-Setguid-tools.txt
}

#
# Find all files with .jsp, .asp, .aspx, .php extentions. Hash them and capture last 1000 lines. For Solaris it simply gzips these files. 
# 
get_pot_webshell(){ #Production
    
    find / -type f \( -iname '*.jsp' -o -iname '*.asp' -o -iname '*.php' -o -iname '*.aspx' \) 2>/dev/null -print0 | xargs -0 sha1sum > $OUTROOT/$OUTDIR/Misc/$OUTFILE-pot-webshell-hashes.txt
    
    find / -type f \( -iname '*.jsp' -o -iname '*.asp' -o -iname '*.php' -o -iname '*.aspx' \) 2>/dev/null -print0 | xargs -0 head -1000 > $OUTROOT/$OUTDIR/Misc/$OUTFILE-pot-webshell-first-1000.txt
    
}
	
# 
# Artefact packaging and clean up
# 
end_collection(){ #Production

	# Archive/Compress files
	echo " "
	echo " Creating $OUTFILE.tar.gz "
	tar -czf $OUTROOT/$OUTFILE_PREFIX$OUTFILE.tar.gz $OUTROOT/$OUTDIR
	
	# Clean-up $OUTDIR directory if the tar exists
	if [ -f $OUTROOT/$OUTFILE_PREFIX$OUTFILE.tar.gz ]; then
	 echo " "
	 echo " Cleaning up!..."
	 rm -r $OUTROOT/$OUTDIR
	fi
	
	# Check if clean-up has been successful
	if [ ! -d $OUTROOT/$OUTDIR ]; then
	 echo " Clean-up Successful!"
	fi
	if [ -d $OUTROOT/$OUTDIR ]; then
	 echo " "
	 echo " WARNING Clean-up has not been successful please manually remove;"
	 echo $OUTROOT/$OUTDIR
	fi
	
	# SHA1 the tar
	 echo " "
	 echo " *************************************************************"
	 echo "  Collection of triage data complete! "
	 echo "  Please submit the following file and SHA1 hash for analysis."
	 echo " *************************************************************"
	 echo " "
	sha1sum $OUTROOT/$OUTFILE_PREFIX$OUTFILE.tar.gz
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
			echo " - Docker and Virtual Machine info..."
			get_docker_info
			echo " - Installed Packages..."
			get_packageinfo_GNU
			vrfy_packageinfo_GNU
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
			
			
		} 2>> $OUTROOT/$OUTDIR/$OUTFILE-console-error-log.txt
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
			vrfy_packageinfo_GNU
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
			
		} 2>> $OUTROOT/$OUTDIR/$OUTFILE-console-error-log.txt
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
			vrfy_packageinfo_Solaris
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
			
		} 2>> $OUTROOT/$OUTDIR/$OUTFILE-console-error-log.txt
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
			
		} 2>> $OUTROOT/$OUTDIR/$OUTFILE-console-error-log.txt
        ;;
		
esac

end_collection
exit
