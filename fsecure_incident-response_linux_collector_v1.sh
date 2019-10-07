#!/bin/bash
#
# FSecure InfoSecurity - Linux Collection Script
#
# This script is maintained by FSecure Consulting.
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
#  - Creates and records MD5 cryptographic hashes of binary files
# The script does this by executing local binaries on your system. It does not install or drop any binaries on your system or change configurations. 
# This script may alter forensic artefacts, it is not recommended where evidence preservation is important.
# 

# Force hostname format
SHORTNAME=$(hostname -s)
# Force date format
DTG=$(date +"%Y%m%d-%H%M")
# Outfile name
OUTFILE=$SHORTNAME-$DTG
#
# Check for root/sudo privileges
#
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
#
# Prompt for output path
#
clear
echo " *************************************************************************************"
echo " * ███████╗      ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ██╗██╗██████╗  *"
echo " * ██╔════╝      ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ██║██║██╔══██╗ *"
echo " * █████╗  █████╗███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ██║██║██████╔╝ *"
echo " * ██╔══╝  ╚════╝╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ██║██║██╔══██╗ *"
echo " * ██║           ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ██║██║██║  ██║ *"
echo " * ╚═╝           ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝╚═╝╚═╝  ╚═╝ *"
echo " *                MWR / F-Secure - Investigations & Incident Response                *"
echo " *************************************************************************************"

OUTPUT=./

echo "Output path is the current working directory"

if [ -d $OUTPUT/FSecure_out ]; then
 echo " "
 echo " ******************************************************"
 echo "  ERROR: Output path directory already exists! " 
 echo " ******************************************************"
 echo " "
 exit
fi
#
# Exit if FSecure-$OUTFILE.tar.gz already exists
#
if [ -f $OUTPUT/FSecure-$OUTFILE.tar.gz ]; then
 echo " "
 echo " ******************************************************"
 echo "  ERROR: FSecure-$OUTFILE.tar.gz already exists "
 echo " ******************************************************"
 echo " "
 exit
fi
#
# Create output directory if does not exist and chmod it
#
if [ ! -d $OUTPUT/FSecure_out ]; then
 mkdir $OUTPUT/FSecure_out
 chmod 600 $OUTPUT/FSecure_out
fi
#
# Start collection
#
 echo " "
 echo " Running Collection Scripts "
 echo " "
#
# ******************************************************************
# INCLUDE ARTIFACTS BELOW
# ******************************************************************
#

#Grab bash history before executing more commands
echo "      Collecting bash history..."
find / -name ".bash_history" -exec tar -rf $OUTPUT/FSecure_out/$OUTFILE-bash_history.tar "{}" \;

# Create a timeline of all files in the following directories: /home/* + var/www/* + /tmp/ + /dev/shm/ + /bin + /sbin
#Collects Access Date,Access Time,Modify Date,Modify Time,Create Date,Create Time,Permissions,UID,Username,GID,Groupname,Size,File of all files in given directory

echo "Creating Timeline of /home/* + var/www/* + /tmp/ + /dev/shm/ directories..."

find /home/ -printf "%Ax,%AT,%Tx,%TT,%Cx,%CT,%m,%U,%u,%G,%g,%s,%p\n" > $OUTPUT/FSecure_out/$OUTFILE-home-dir-timeline;

find /var/www/ -printf "%Ax,%AT,%Tx,%TT,%Cx,%CT,%m,%U,%u,%G,%g,%s,%p\n"  > $OUTPUT/FSecure_out/$OUTFILE-var-www-dir-timeline;

find /tmp/ -printf "%Ax,%AT,%Tx,%TT,%Cx,%CT,%m,%U,%u,%G,%g,%s,%p\n"  > $OUTPUT/FSecure_out/$OUTFILE-tmp-dir-timeline;

find /dev/shm/ -printf "%Ax,%AT,%Tx,%TT,%Cx,%CT,%m,%U,%u,%G,%g,%s,%p\n"  > $OUTPUT/FSecure_out/$OUTFILE-dev-shm-dir-timeline;

find /bin/ -printf "%Ax,%AT,%Tx,%TT,%Cx,%CT,%m,%U,%u,%G,%g,%s,%p\n"  > $OUTPUT/FSecure_out/$OUTFILE-bin-dir-timeline;

find /sbin/ -printf "%Ax,%AT,%Tx,%TT,%Cx,%CT,%m,%U,%u,%G,%g,%s,%p\n"  > $OUTPUT/FSecure_out/$OUTFILE-sbin-dir-timeline;
#***************************************************************
#
echo " Volatile Data..."
echo "      Collecting Running Processes.."
ps aux > $OUTPUT/FSecure_out/$OUTFILE-processes.txt
pslist=$(ps aux | egrep -v "^USER.*PID.*CPU.*MEM.*VSZ.*RSS.*TTY.*STAT.*START.*TIME.*COMMAND")
linesinspace="$(echo "$pslist" | sed 's/ \+/ /gp' | uniq)"
linetab=$(echo "$linesinspace" | tr " " "	")

echo "$linetab" | while IFS= read -r line
do
	user=$(echo "$line" | cut -d "	" -f 1)
	cmd=$(echo "$line" | cut -d "	" -f 11)
	psentry=$(echo $cmd'	'$user'	'$SHORTNAME)
	echo -e $psentry >> $OUTPUT/FSecure_out/$OUTFILE-processes-list.txt
done

ls /proc/ | grep '[0-9]' | grep -v '[a-zA-Z]'| wc -l > $OUTPUT/FSecure_out/$OUTFILE-num-ps #number of processes according to /proc
cat $OUTPUT/FSecure_out/$OUTFILE-processes.txt | sed -n '1!p' | wc -l > $OUTPUT/FSecure_out/$OUTFILE-num-proc #number of processes according to /ps

#number of processes according to /ps
lsof > $OUTPUT/FSecure_out/$OUTFILE-lsof-processes #lists files opened by a given process

md5sum '/usr/bin/ps'> $OUTPUT/FSecure_out/$OUTFILE-md5-ps #hashing the ps bin

find /proc -maxdepth 2 -wholename '/proc/[0-9]*/status' | xargs cat

# computing the hash of all running processes
for f in `find -L /proc/[0-9]*/exe -exec ls -la {} \; 2>/dev/null | awk '{print $11}' | uniq | sed '/^$/d'`; do md5sum $f; done > $OUTPUT/FSecure_out/$OUTFILE-processhashes.txt

#
echo "      Collecting Network Info..."
netstat -ano > $OUTPUT/FSecure_out/$OUTFILE-netstat.txt
netstat -antup > $OUTPUT/FSecure_out/$OUTFILE-netstat-antup.txt
#
netlist=$(netstat -latupn | egrep -v "(Active Internet connections|Proto.*Recv-Q.*Send-Q.*Local)")
linesinspace="$(echo "$netlist" | sed 's/ \+/ /gp' | uniq)"
linetab=$(echo "$linesinspace" | tr " " "	")
linetabhost=$(echo "$linetab" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
echo -e $linetabhost >> $OUTPUT/FSecure_out/$OUTFILE-netstat-list.txt
#
ifconfig -a > $OUTPUT/FSecure_out/$OUTFILE-ifconfig.txt
route > $OUTPUT/FSecure_out/$OUTFILE-routetable.txt
cat /etc/resolv.conf > $OUTPUT/FSecure_out/$OUTFILE-dhcp.txt
cat /etc/hosts > $OUTPUT/FSecure_out/$OUTFILE-hosts.txt
cat /etc/host.conf > $OUTPUT/FSecure_out/$OUTFILE-host.conf.txt
cat /etc/hosts.allow > $OUTPUT/FSecure_out/$OUTFILE-hosts.allow.txt
cat /etc/hosts.deny > $OUTPUT/FSecure_out/$OUTFILE-hosts.deny.txt
cat /etc/ssh/ssh_config > $OUTPUT/FSecure_out/$OUTFILE-ssh_config.txt
cat /etc/ssh/sshd_config > $OUTPUT/FSecure_out/$OUTFILE-sshd_config.txt
#
echo "      Collecting logged in users..."
who -a > $OUTPUT/FSecure_out/$OUTFILE-who.txt
#
echo "      Collecting 'w'..."
w > $OUTPUT/FSecure_out/$OUTFILE-whoandwhat.txt
#
echo "      Collecting /var/log directory..."
tar -zcf $OUTPUT/FSecure_out/$OUTFILE-var_logs.tar.gz /var/log
#
echo " Collecting execution artefacts..."

echo "	    Collecting bashrc and .bash_profile (persistence)"
find / -name ".bashrc" -exec tar -rf $OUTPUT/FSecure_out/$OUTFILE-bashrc.tar "{}" \;
find / -name ".bash_profile" -exec tar -rf $OUTPUT/FSecure_out/$OUTFILE-bash_profile.tar "{}" \;
#
echo "      Collecting bad logins..."
lastb > $OUTPUT/FSecure_out/$OUTFILE-lastbad.txt
#
echo "      Collecting Login History..."
last > $OUTPUT/FSecure_out/$OUTFILE-last.txt
#
echo "      Collecting lastlog..."
lastlog > $OUTPUT/FSecure_out/$OUTFILE-lastlog.txt
#
echo "	 Parsing wtmp last log - analyse logins..."
last -Faiwx -f /var/log/wtmp > $OUTPUT/FSecure_out/$OUTFILE-wtmp-lastlog.txt
last -Faiwx -f /var/log/wtmp.1 >> $OUTPUT/FSecure_out/$OUTFILE-wtmp-lastlog.txt
#
echo "	 Parsing btmp last log - analyse failed logins..."
lastb -Faiwx -f /var/log/btmp > $OUTPUT/FSecure_out/$OUTFILE-btmp-lastlog.txt
lastb -Faiwx -f /var/log/btmp.1 >> $OUTPUT/FSecure_out/$OUTFILE-btmp-lastlog.txt
#
echo " System Configuration..."
#
echo "      Collecting ssh authorized keys..."
for X in $(cut -f6 -d ':' /etc/passwd |sort |uniq); do
    if [ -s "${X}/.ssh/authorized_keys" ]; then
        cat "${X}/.ssh/authorized_keys" >> $OUTPUT/FSecure_out/$OUTFILE-authorized-keys.txt
    fi
done
#cat ~/.ssh/known_hosts > $OUTPUT/FSecure_out/$OUTFILE-known-hosts.txt
#
echo "      Collecting ssh known hosts..."
for X in $(cut -f6 -d ':' /etc/passwd |sort |uniq); do
    if [ -s "${X}/.ssh/known_hosts" ]; then
        cat "${X}/.ssh/known_hosts" >> $OUTPUT/FSecure_out/$OUTFILE-known-hosts.txt
    fi
done


#.viminfo
echo "      Collecting .viminfo files..." 
find /home/*/.viminfo -exec tar -rf $OUTPUT/FSecure_out/$OUTFILE-viminfo.tar "{}" \;

#cat ~/.ssh/authorized_keys > $OUTPUT/FSecure_out/$OUTFILE-authorized-keys.txt
#
echo "      Collecting user info..."
cat /etc/passwd > $OUTPUT/FSecure_out/$OUTFILE-passwd.txt
#cat /etc/shadow > $OUTPUT/FSecure_out/$OUTFILE-shadow.txt #removed as per client request
cat /etc/group > $OUTPUT/FSecure_out/$OUTFILE-group.txt
cat /etc/sudoers > $OUTPUT/FSecure_out/$OUTFILE-sudoers.txt
cat /etc/sudoers.d/* >> $OUTPUT/FSecure_out/$OUTFILE-sudoers.txt

#
echo "      Collecting IPtables..."
iptables -L > $OUTPUT/FSecure_out/$OUTFILE-iptables.txt
#
echo "      Collecting SELinux status..."
sestatus -v > $OUTPUT/FSecure_out/$OUTFILE-selinux.txt
#
echo "      Collecting SELinux booleans..."
getsebool -a > $OUTPUT/FSecure_out/$OUTFILE-getsebool.txt
echo "      Collecting rc.local..."
cat /etc/rc.local > $OUTPUT/FSecure_out/$OUTFILE-rc.local.txt
#
echo "      Collecting inittab..."
cat /etc/inittab > $OUTPUT/FSecure_out/$OUTFILE-inittab.txt
#
echo "      Collecting aliases..."
cat /etc/aliases > $OUTPUT/FSecure_out/$OUTFILE-aliases.txt
#
echo "      Collecting Memory and CPU info..."
cat /proc/meminfo > $OUTPUT/FSecure_out/$OUTFILE-meminfo.txt
cat /proc/cpuinfo > $OUTPUT/FSecure_out/$OUTFILE-cpuinfo.txt
#
echo "      Collecting df..."
df > $OUTPUT/FSecure_out/$OUTFILE-df.txt
#
echo "      Collecting attached USB device info..."
lsusb -v > $OUTPUT/FSecure_out/$OUTFILE-lsusb.txt
#
echo " Kernel Checks..."
cat /etc/*release > $OUTPUT/FSecure_out/$OUTFILE-release.txt
#
echo "      Collecting lsmod..."
lsmod=$(lsmod | egrep -v "^Module.*Size.*Used by")
linesinspace="$(echo "$lsmod" | sed 's/ \+/ /gp' | uniq)"
linetab=$(echo "$linesinspace" | tr " " "	")
linetabhost=$(echo "$linetab" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME "'/'; done)
echo "$linetabhost" > $OUTPUT/FSecure_out/$OUTFILE-lsmod.txt
#
echo "      Collecting proc/modules..."
procmod=$(cat '/proc/modules')
linetab=$(echo "$procmod" | tr " " "	")
linetabhost=$(echo "$linetab" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
echo "$linetabhost" > $OUTPUT/FSecure_out/$OUTFILE-procmod.txt
#
echo "      Diffing lsmod vs proc/modules..."
procmod=$(cat '/proc/modules')
lsmod=$(lsmod | egrep -v "^Module.*Size.*Used by")
linesinspacelsmod="$(echo "$lsmod" | sed 's/ \+/ /gp' | uniq)"
linetablsmod=$(echo "$linesinspacelsmod" | tr " " ":")
lsmodcut=$(echo "$linetablsmod" | cut -d ":" -f 1,2)
linetabprocmod=$(echo "$procmod" | tr " " ":")
procmodcut=$(echo "$linetabprocmod" | cut -d ":" -f 1,2)
echo "$lsmodcut" > $OUTPUT/FSecure_out/$OUTFILE-lsmoddiff.txt
echo "$procmodcut" > $OUTPUT/FSecure_out/$OUTFILE-procmoddiff.txt
diffout=$(diff $OUTPUT/FSecure_out/$OUTFILE-lsmoddiff.txt $OUTPUT/FSecure_out/$OUTFILE-procmoddiff.txt)
if echo $diffout | egrep -q ".+"; then
	echo "$diffout"	"$SHORTNAME" > $OUTPUT/FSecure_out/$OUTFILE-lsmod-procmod-diff.txt 
fi
rm $OUTPUT/FSecure_out/$OUTFILE-lsmoddiff.txt
rm $OUTPUT/FSecure_out/$OUTFILE-procmoddiff.txt
#
echo " Persistence Checks..."
#
echo " Collecting service status all..."
service --status-all > $OUTPUT/FSecure_out/$OUTFILE-service_status.txt
#
echo "      Collecting atjobs..."
jobfilelist=$(find '/var/spool/cron/atjobs' -type f -size +50c)
echo "$jobfilelist" | while IFS= read -r jobfile
do
	cmdlist=$(cat "$jobfile" | egrep -v "(^#|^:|export|umask)" | egrep "[a-zA-Z]")
	echo "$cmdlist" | while IFS= read -r cmd
	do
		jobentry=$(echo $jobfile'	'$cmd'	'$SHORTNAME)
		printf "$jobentry\n"
		echo -e $jobentry >> $OUTPUT/FSecure_out/$OUTFILE-persistence-atjobs.txt
	done
done
#
echo "      Collecting crontab..."
#cat /etc/crontab > $OUTPUT/FSecure_out/$OUTFILE-persistence-crontab.txt
oscheckdir='/etc/*release'
if ls $oscheckdir 1> /dev/null 2>&1; then
	oscheck=$(cat $oscheckdir)
	oscheck=$(echo $oscheck | tr '[:upper:]' '[:lower:]')
fi
uname=$(uname -a | tr '[:upper:]' '[:lower:]')
cronlist=""
cronlocation='/etc/crontab'
# ToDo - Add more - Arch? Slackware?
if echo $oscheck | egrep -q ".*(ubuntu|debian).*"; then
	usercronlocation='/var/spool/cron/crontabs'
elif echo $oscheck | egrep -q ".*(red hat|rhel|fedora|centos).*" ; then
	usercronlocation='/var/spool/cron'
elif echo $oscheck | egrep -q ".*suse.*" ; then
	usercronlocation='/var/spool/cron/tabs'
#elif echo $oscheck | egrep -q ".*arch linux.*" ; then
elif echo $uname | egrep -q ".*bsd.*"; then
	usercronlocation='/var/cron/tabs'
elif echo $uname | egrep -q ".*aix.*"; then
	usercronlocation='/var/spool/cron'
elif echo $uname | egrep -q ".*hp-ux.*"; then
	usercronlocation='/var/spool/cron/crontabs'
elif echo $uname | egrep -q ".*(sunos|solaris).*"; then
	usercronlocation='/var/spool/cron/crontabs'
elif echo $uname | egrep -q ".*darwin.*"; then
	usercronlocation='/usr/lib/cron/tabs'
else
	echo "Error: Incompatible Distribution - Check Following Results"
	echo $oscheck
	echo $uname
	exit 1
fi
# System Crontab
value=$(cat $cronlocation)
lines=$(echo "$value" | egrep "^([0-9]|@|\*)")
case "$lines" in
  *@yearly*) lines=$(echo "$lines" | sed 's/@yearly/0 0 1 1 */g');;
esac
case "$lines" in
  *@annually*) lines=$(echo "$lines" | sed 's/@annually/0 0 1 1 */g');;
esac
case "$lines" in
  *@monthly*) lines=$(echo "$lines" | sed 's/@monthly/0 0 1 * */g')
esac
case "$lines" in
  *@weekly*) lines=$(echo "$lines" | sed 's/@weekly/0 0 * * 0/g')
esac
case "$lines" in
  *@daily*) lines=$(echo "$lines" | sed 's/@daily/0 0 * * */g')
esac
case "$lines" in
  *@midnight*) lines=$(echo "$lines" | sed 's/@midnight/0 0 * * */g')
esac
case "$lines" in
  *@hourly*) lines=$(echo "$lines" | sed 's/@hourly/0 * * * */g')
esac
case "$lines" in
  *@reboot*) lines=$(echo "$lines" | sed 's/@reboot/reboot N N N N/g')
esac
linesinspace="$(echo "$lines" | sed 's/ \+/ /gp' | uniq)"
linesspace=$(echo "$linesinspace" | while IFS= read -r line ; do echo "$line" | tr "	" " "; done)
linetab=$(echo "$linesspace" | sed 's/ /    /1'| sed 's/ /    /5' | sed 's/ /    /9'| sed 's/ /    /13'| sed 's/ /    /17' | sed 's/ /    /21' | sed 's/    /	/g')
linetabhost1=$(echo "$linetab" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
cronlist=$linetabhost1
# User Crontabs 
for i in $(ls $usercronlocation)
do
	value=$(cat $usercronlocation/$i)
	lines=$(echo "$value" | egrep "^([0-9]|@|\*)")
	case "$lines" in
	  *@yearly*) lines=$(echo "$lines" | sed 's/@yearly/0 0 1 1 */g');;
	esac
	case "$lines" in
	  *@annually*) lines=$(echo "$lines" | sed 's/@annually/0 0 1 1 */g');;
	esac
	case "$lines" in
	  *@monthly*) lines=$(echo "$lines" | sed 's/@monthly/0 0 1 * */g')
	esac
	case "$lines" in
	  *@weekly*) lines=$(echo "$lines" | sed 's/@weekly/0 0 * * 0/g')
	esac
	case "$lines" in
	  *@daily*) lines=$(echo "$lines" | sed 's/@daily/0 0 * * */g')
	esac
	case "$lines" in
	  *@midnight*) lines=$(echo "$lines" | sed 's/@midnight/0 0 * * */g')
	esac
	case "$lines" in
	  *@hourly*) lines=$(echo "$lines" | sed 's/@hourly/0 * * * */g')
	esac
	case "$lines" in
	  *@reboot*) lines=$(echo "$lines" | sed 's/@reboot/reboot N N N N/g')
	esac
	linesinspace="$(echo "$lines" | sed 's/ \+/ /gp' | uniq)"
	addfield=$(echo "$linesinspace" | while IFS= read -r line ; do echo "$line" | sed 's/ / '"$i "'/5'; done)
	linesspace=$(echo "$addfield" | while IFS= read -r line ; do echo "$line" | tr "	" " "; done)
	linetab=$(echo "$linesspace" | sed 's/ /    /1'| sed 's/ /    /5' | sed 's/ /    /9'| sed 's/ /    /13'| sed 's/ /    /17' | sed 's/ /    /21' | sed 's/    /	/g')
	if echo $linetab | egrep -q "[a-zA-Z0-9]"; then
		linetabhost2=$(echo "$linetab" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
		cronlist=$cronlist'\n'$linetabhost2
	fi
done
crond='/etc/cron.d'
cronhourly='/etc/cron.hourly'
crondaily='/etc/cron.daily'
cronweekly='/etc/cron.weekly'
cronmonthly='/etc/cron.monthly'
# Cron.d Directory
if [ -d $crond ]
then
	for h in $(ls $crond)
	do
		value=$(cat $crond/$h)
		lines=$(echo "$value" | egrep "^([0-9]|@|\*)")
		case "$lines" in
		  *@yearly*) lines=$(echo "$lines" | sed 's/@yearly/0 0 1 1 */g');;
		esac
		case "$lines" in
		  *@annually*) lines=$(echo "$lines" | sed 's/@annually/0 0 1 1 */g');;
		esac
		case "$lines" in
		  *@monthly*) lines=$(echo "$lines" | sed 's/@monthly/0 0 1 * */g')
		esac
		case "$lines" in
		  *@weekly*) lines=$(echo "$lines" | sed 's/@weekly/0 0 * * 0/g')
		esac
		case "$lines" in
		  *@daily*) lines=$(echo "$lines" | sed 's/@daily/0 0 * * */g')
		esac
		case "$lines" in
		  *@midnight*) lines=$(echo "$lines" | sed 's/@midnight/0 0 * * */g')
		esac
		case "$lines" in
		  *@hourly*) lines=$(echo "$lines" | sed 's/@hourly/0 * * * */g')
		esac
		case "$lines" in
		  *@reboot*) lines=$(echo "$lines" | sed 's/@reboot/reboot N N N N/g')
		esac
		linesinspace="$(echo "$lines" | sed 's/ \+/ /gp' | uniq)"
		linesspace=$(echo "$linesinspace" | while IFS= read -r line ; do echo "$line" | tr "	" " "; done)
		linetab=$(echo "$linesspace" | sed 's/ /    /1'| sed 's/ /    /5' | sed 's/ /    /9'| sed 's/ /    /13'| sed 's/ /    /17' | sed 's/ /    /21' | sed 's/    /	/g')
		linetabhost3=$(echo "$linetab" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
		cronlist=$cronlist'\n'$linetabhost3
	done
fi
# Individual Cron Folders
if [ -d $cronhourly ]
then
	for j in $(ls -A $cronhourly)
	do
		value=$(ls -A $cronhourly/$j)
		addowner=$(for j in $(ls $cronhourly); do ls -lA $cronhourly/$j | awk '{print $3,$9}' | sed 's|'$cronhourly/'|	|'; done)
		addfreq=$(echo "$addowner" | while IFS= read -r line ; do echo "$line" | sed 's/^/0	*	*	*	*	/'; done)
		addhost=$(echo "$addfreq" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
	done
	cronlist=$cronlist'\n'$addhost
fi

if [ -d $crondaily ]
then
	for j in $(ls -A $crondaily)
	do
		value=$(ls -A $crondaily/$j)
		addowner=$(for j in $(ls $crondaily); do ls -lA $crondaily/$j | awk '{print $3,$9}' | sed 's|'$crondaily/'|	|'; done)
		addfreq=$(echo "$addowner" | while IFS= read -r line ; do echo "$line" | sed 's/^/0	0	*	*	*	/'; done)
		addhost=$(echo "$addfreq" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
	done
	cronlist=$cronlist'\n'$addhost
fi
if [ -d $cronweekly ]
then
	for j in $(ls -A $cronweekly)
	do
		value=$(ls -A $cronweekly/$j)
		addowner=$(for j in $(ls $cronweekly); do ls -lA $cronweekly/$j | awk '{print $3,$9}' | sed 's|'$cronweekly/'|	|'; done)
		addfreq=$(echo "$addowner" | while IFS= read -r line ; do echo "$line" | sed 's/^/0	0	*	*	0	/'; done)
		addhost=$(echo "$addfreq" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
	done
	cronlist=$cronlist'\n'$addhost
fi
if [ -d $cronmonthly ]
then
	for j in $(ls -A $cronmonthly)
	do
		value=$(ls -A $cronmonthly/$j)
		addowner=$(for j in $(ls $cronmonthly); do ls -lA $cronmonthly/$j | awk '{print $3,$9}' | sed 's|'$cronmonthly/'|	|'; done)
		addfreq=$(echo "$addowner" | while IFS= read -r line ; do echo "$line" | sed 's/^/0	0	1	*	*	/'; done)
		addhost=$(echo "$addfreq" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
	done
	cronlist=$cronlist'\n'$addhost
fi
echo -e "$cronlist" > $OUTPUT/FSecure_out/$OUTFILE-persistence-cronlist.txt
#
echo "      Collecting anacron..."
oscheckdir='/etc/*release'
if ls $oscheckdir 1> /dev/null 2>&1; then
	oscheck=$(cat $oscheckdir)
	oscheck=$(echo $oscheck | tr '[:upper:]' '[:lower:]')
fi
uname=$(uname -a | tr '[:upper:]' '[:lower:]')
if echo $oscheck | egrep -q ".*(ubuntu|debian).*"; then
	anacronlocation='/etc/anacrontab'
elif echo $oscheck | egrep -q ".*(red hat|rhel|fedora|centos).*" ; then
	anacronlocation='/etc/anacrontab'
elif echo $oscheck | egrep -q ".*suse.*" ; then
	anacronlocation='/etc/anacrontab'
#elif echo $oscheck | egrep -q ".*arch linux.*" ; then
elif echo $uname | egrep -q ".*bsd.*"; then
	anacronlocation='/usr/local/etc/anacrontab'
elif echo $uname | egrep -q ".*aix.*"; then
	anacronlocation='/etc/anacron'
elif echo $uname | egrep -q ".*hp-ux.*"; then
	anacronlocation='/etc/anacrontab'
elif echo $uname | egrep -q ".*(sunos|solaris).*"; then
	anacronlocation='/etc/anacrontab'
elif echo $uname | egrep -q ".*darwin.*"; then
	:
else
	echo "Error: Incompatible Distribution - Check Following Results"
	echo $oscheck
	echo $uname
	exit 1
fi
if ls $anacronlocation 1> /dev/null 2>&1; then
	value=$(cat $anacronlocation)
	lines=$(echo "$value" | egrep "^([0-9]|@|\*)")
	addhost=$(echo "$lines" | while IFS= read -r line ; do echo "$line" | sed 's/.*/&'"	$SHORTNAME"'/'; done)
fi
echo -e "$addhost" > $OUTPUT/FSecure_out/$OUTFILE-persistence-anacron.txt
#
echo "      Collecting systemd..." 
systemddir='/etc/systemd/system'
systemdlist=""
if ls $systemddir 1> /dev/null 2>&1; then
	for i in $(find $systemddir -iname '*.service')
	do
		name=$(echo $i | sed 's|.*/||')
		cmd=$(cat $i | grep ExecStart | sed 's/ExecStart=//')
		dt=$(ls -lA $i | awk '{print $6,$7,$8}')
		user=$(ls -lA $i | awk '{print $3}')
		systemd=$(echo $dt'	'$user'	'$name'	'$cmd'	'$SHORTNAME)
		systemdlist=$systemdlist'\n'$systemd
	done
fi
echo -e "$systemdlist" > $OUTPUT/FSecure_out/$OUTFILE-persistence-systemdlist.txt
#
echo "      Collecting shellrc..." 
etcdir=$(find /etc/ -type f | egrep '/etc.*(shrc$|/profile$|zprofile$|zlogin$|zshenv$)' | grep -v /skel/)
homedir=$(find /home/ -type f | egrep '.*(\.profile$|shrc$|sh_profile$|zprofile$|zlogin$|zshenv$)') 
rootdir=$(find /root/ -type f | egrep '.*(\.profile$|shrc$|sh_profile$|zprofile$|zlogin$|zshenv$)') 
echo "$etcdir" | while IFS= read -r line
do
	file=$(cat "$line" | egrep -v "^#" | egrep [a-zA-Z0-9])
	echo "$file" | while IFS= read -r line2
	do
		cmd="$line2"
		shellrcentryetc=$(echo $line'	'$cmd'	'$SHORTNAME)
		echo -e $shellrcentryetc >> $OUTPUT/FSecure_out/$OUTFILE-persistence-shellrc-etc.txt
	done 
done
#
echo "$homedir" | while IFS= read -r line
do
	file=$(cat "$line" | egrep -v "^#" | egrep [a-zA-Z0-9])
	echo "$file" | while IFS= read -r line2
	do
		cmd="$line2"
		shellrcentryhome=$(echo $line'	'$cmd'	'$SHORTNAME)
		echo $shellrcentryhome >> $OUTPUT/FSecure_out/$OUTFILE-persistence-shellrc-home.txt
	done
done
#
echo "$rootdir" | while IFS= read -r line
do
	file=$(cat "$line" | egrep -v "^#" | egrep [a-zA-Z0-9])
	echo "$file" | while IFS= read -r line2
	do
		cmd="$line2"
		shellrcentryroot=$(echo $line'	'$cmd'	'$SHORTNAME)
		echo $shellrcentryroot >> $OUTPUT/FSecure_out/$OUTFILE-persistence-shellrc-root.txt
	done
done
#
echo "      Collecting rc-scripts..." 
rcinitpath='/etc/init.d/rc.local'
rcpath='/etc/rc.local'
rcsyspath='/etc/rc.d/rc.sysinit'
rcbootpath='/etc/rc.boot'
sbinrcbootpath='/sbin/rc.boot'
if ls $rcinitpath 1> /dev/null 2>&1; then
	if test -x $rcinitpath
	then 
		rclocal=$(cat $rcinitpath | egrep -v "^#" | egrep "[a-zA-Z0-9]" | egrep -v "^PATH=")
	fi
fi
if ls $rcpath 1> /dev/null 2>&1; then
	if test -x $rcpath
	then 
		rc=$(cat $rcpath | egrep -v "^#" | egrep "[a-zA-Z0-9]" | egrep -v "^PATH=")
	fi
fi
if ls $rcsyspath 1> /dev/null 2>&1; then
	if test -x $rcsyspath
	then 
		rcsys=$(cat $rcsyspath | egrep -v "^#" | egrep "[a-zA-Z0-9]" | egrep -v "^PATH=")
	fi
fi
if ls $rcbootpath 1> /dev/null 2>&1; then
	if test -x $rcbootpath
	then 
		rcboot=$(cat $rcbootpath | egrep -v "^#" | egrep "[a-zA-Z0-9]" | egrep -v "^PATH=")
	fi
fi
if ls $sbinrcbootpath 1> /dev/null 2>&1; then
	if test -x $sbinrcbootpath
	then 
		sbinrcboot=$(cat $sbinrcbootpath | egrep -v "^#" | egrep "[a-zA-Z0-9]" | egrep -v "^PATH=")
	fi
fi
echo "$rclocal" | while IFS= read -r line
do
	cmd=$(echo "$line")
	rcentry=$(echo $rcinitpath'	'$cmd'	'$SHORTNAME)
	echo $rcentry >> $OUTPUT/FSecure_out/$OUTFILE-persistence-rc-scripts.txt
done
echo "$rc" | while IFS= read -r line
do
	cmd=$(echo "$line")
	rcentry=$(echo $rcpath'	'$cmd'	'$SHORTNAME)
	echo $rcentry >> $OUTPUT/FSecure_out/$OUTFILE-persistence-rc-scripts.txt
done
echo "$rcsys" | while IFS= read -r line
do
	cmd=$(echo "$line")
	rcentry=$(echo $rcsyspath'	'$cmd'	'$SHORTNAME)
	echo $rcentry >> $OUTPUT/FSecure_out/$OUTFILE-persistence-rc-scripts.txt
done
echo "$rcboot" | while IFS= read -r line
do
	cmd=$(echo "$line")
	rcentry=$(echo $rcbootpath'	'$cmd'	'$SHORTNAME)
	echo $rcentry >> $OUTPUT/FSecure_out/$OUTFILE-persistence-rc-scripts.txt
done
echo "$sbinrcboot" | while IFS= read -r line
do
	cmd=$(echo "$line")
	rcentry=$(echo $sbinrcbootpath'	'$cmd'	'$SHORTNAME)
	echo $rcentry >> $OUTPUT/FSecure_out/$OUTFILE-persistence-rc-scripts.txt
done
#
echo "      Collecting profile.d..." 
etcprof='/etc/profile.d'
if ls $etcprof 1> /dev/null 2>&1; then
	files=$(ls $etcprof)
	echo "$files" | while IFS= read -r line
	do
		dt=$(ls -lA $etcprof/$line | awk '{print $6,$7,$8}')
		user=$(ls -lA $etcprof/$line | awk '{print $3}')
		etcprofentry=$(echo $dt'	'$user'		'$line'	'$SHORTNAME) 
		echo $etcprofentry >> $OUTPUT/FSecure_out/$OUTFILE-persistence-profiled.txt
	done
fi
#
echo "      Collecting inittab..." 
inittab='/etc/inittab'
if ls $inittab 1> /dev/null 2>&1; then
	entries=$(cat $inittab | egrep -v "^#")
	echo "$entries" | while IFS= read -r line
	do
		tab=$(echo "$line" | sed 's/:/	/g')
		addhost=$(echo "$tab" | sed 's/.*/&'"	$SHORTNAME"'/')
		echo $addhost >> $OUTPUT/FSecure_out/$OUTFILE-persistence-inittab.txt
	done
fi
#
echo "      Collecting initd..."
oscheckdir='/etc/*release'
if ls $oscheckdir 1> /dev/null 2>&1; then
	oscheck=$(cat $oscheckdir)
	oscheck=$(echo $oscheck | tr '[:upper:]' '[:lower:]')
fi
uname=$(uname -a | tr '[:upper:]' '[:lower:]')
initdlist=""
if echo $oscheck | egrep -q ".*(ubuntu|debian).*"; then
	initd='/etc/init.d'
elif echo $oscheck | egrep -q ".*(red hat|rhel|fedora|centos).*" ; then
	initd='/etc/init.d'
elif echo $oscheck | egrep -q ".*suse.*" ; then
	initd='/etc/init.d'
#elif echo $oscheck | egrep -q ".*arch linux.*" ; then
elif echo $uname | egrep -q ".*bsd.*"; then
	initd='/etc/rc.d'
	localinitd='/usr/local/etc/rc.d'
elif echo $uname | egrep -q ".*aix.*"; then
	initd='/etc/rc.d/init.d'
elif echo $uname | egrep -q ".*hp-ux.*"; then
	initd='/sbin/init.d'
elif echo $uname | egrep -q ".*(sunos|solaris).*"; then
	initd='/etc/init.d'
else
	echo "Error: Incompatible Distribution - Check Following Results"
	echo $oscheck
	echo $uname
	exit 1
fi
for i in $(ls -A $initd)
do
	if test -x $initd/$i 
	then
		temp=$(ls -lA $initd/$i | awk '{print $1,$2,$3,$4,$5,$9}' | sed 's|'$initd/'||')
		temptab=$(echo "$temp" | sed 's/ /	/g')
		addhost=$(echo "$temptab" | sed 's/.*/&'"	$SHORTNAME"'/')
		dt=$(ls -lA $initd/$i | awk '{print $6,$7,$8}')
		adddate=$(echo "$addhost" | sed 's/^/'"$dt	"'/')
		initdlist=$initdlist'\n'$adddate
	fi
done
if [ -d $localinitd ]
then
	for i in $(ls -A $localinitd)
	do
		if test -x $localinitd/$i 
		then
			temp=$(ls -lA $localinitd/$i | awk '{print $1,$2,$3,$4,$5,$9}' | sed 's|'$localinitd/'||')
			temptab=$(echo "$temp" | sed 's/ /	/g')
			addhost=$(echo "$temptab" | sed 's/.*/&'"	$SHORTNAME"'/')
			dt=$(ls -lA $localinitd/$i | awk '{print $6,$7,$8}')
			adddate=$(echo "$addhost" | sed 's/^/'"$dt	"'/')
			initdlist=$initdlist'\n'$adddate
		fi
	done
fi
echo -e $initdlist >> $OUTPUT/FSecure_out/$OUTFILE-persistence-initd.txt
#
echo " Hashing bin files..."
pathdirs=$(echo $PATH | sed 's/:/\n/g')
printf "$pathdirs" | while IFS= read -r dir
do
	md5list=$(md5sum "$dir"/*)
	echo "$md5list" | while IFS= read -r md5
	do
		md5sinspace="$(echo "$md5" | sed 's/ \+/ /gp' | uniq)"
		md5tab=$(echo $md5sinspace | tr " " "	") 
		md5entry=$(echo "$md5tab"'	'$SHORTNAME)
		#printf "$md5entry\n"
		echo -e $md5entry >> $OUTPUT/FSecure_out/$OUTFILE-binhashes.txt
	done
done

echo "Grabbing all packages for later comparison"
#echo "[*] Finding all files with +x attributes (executables), and getting file type"
find / -type f -executable -exec file {} \; > $OUTPUT/FSecure_out/$OUTFILE-tmp-executable-files
# generate new file from the above without executable type metadata for later diff operation
awk -F ":" '{print $1}' $OUTPUT/FSecure_out/$OUTFILE-tmp-executable-files | sort > $OUTPUT/FSecure_out/$OUTFILE-tmp-executable-files-for-diff
#echo "[*] Find types of executable"
cat $OUTPUT/FSecure_out/$OUTFILE-tmp-executable-files | awk -F":" '{print $2}' | awk -F"," '{print $1}' | sort | uniq | grep -i 'script\|ELF\|executable' > $OUTPUT/FSecure_out/$OUTFILE-tmp-types
#echo "[*] Filtering types to include only ELF, scripts and generic executables"
grep $OUTPUT/FSecure_out/$OUTFILE-tmp-executable-files -f $OUTPUT/FSecure_out/$OUTFILE-tmp-types | awk -F":" '{print $1}' | awk -F":" '{print $1}' | sort > $OUTPUT/FSecure_out/$OUTFILE-executables-list
#echo "[*] Finding all files in all rpm packages"
if [ -f "/usr/bin/dpkg" ]; then
   for i in `dpkg-query -f '${binary:Package}\n' -W`; do dpkg --listfiles $i | grep -v "\[\|\]\|(\|)\|'" | sort >> $OUTPUT/FSecure_out/$OUTFILE-package-list; done
else
   rpm -qla | grep -v "\[\|\]\|(\|)\|'" | sort > $OUTPUT/FSecure_out/$OUTFILE-package-list
fi
echo "[*] Diff-ing list to find all executables that are not part of packages"
diff $OUTPUT/FSecure_out/$OUTFILE-tmp-executable-files-for-diff $OUTPUT/FSecure_out/$OUTFILE-package-list | grep "^<" > $OUTPUT/FSecure_out/$OUTFILE-packages-result.txt

#
# ******************************************************************
# END OF ARTIFACT COLLECTION
# ******************************************************************
#
# tar up
#
echo " "
echo " Creating $OUTFILE.tar.gz "
tar -zcf $OUTPUT/FSecure-$OUTFILE.tar.gz $OUTPUT/FSecure_out
#
# Clean-up FSecure_out directory if the tar exists
#
if [ -f $OUTPUT/FSecure-$OUTFILE.tar.gz ]; then
 echo " "
 echo " Cleaning up!..."
 rm -r $OUTPUT/FSecure_out
fi
# Check if clean-up has been successful
if [ ! -d $OUTPUT/FSecure_out ]; then
 echo " Clean-up Successful!"
fi
if [ -d $OUTPUT/FSecure_out ]; then
 echo " "
 echo " WARNING Clean-up has not been successful please manually remove;"
 echo $OUTPUT/FSecure_out
fi
#
# md5 the tar
#
 echo " "
 echo " *************************************************************"
 echo "  Collection of diagnostics data Complete! "
 echo "  Please submit the following file and MD5 hash for analysis."
 echo " *************************************************************"
 echo " "
md5sum $OUTPUT/FSecure-$OUTFILE.tar.gz
 echo " "

# Exit the script
exit
