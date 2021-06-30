#!/bin/bash
# This script is used to extract artefacts gathered with F-Secure Cat-Scale Linux Data Collection script version 1.0 release 2020-07-21.
# 
if [ -x "$(which rename 2>/dev/null)" ]; then
	# all is well
	echo "Let's do this"
else
	echo "rename command missing.Please install rename."
	exit 1
fi

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
 echo "  This is required for extraction of the archives with character (unbuffered) special."
 echo " "
 echo " ***************************************************************"
 echo " "
 exit
fi
}

#This is where all the dirty work happens. Code needs to be prettied up. 
extract()
{
		# strip leading dir and extension
		FILE=$(echo $1 | cut -d'_' -f 2 |cut -d'.' -f 1 )
		echo -n $FILE
		if [ -d extracted/$FILE ]; then
			echo  " Folder Already Exists. Skipping..."
		else
			mkdir -p extracted/$FILE
			tar -xf $1 --strip-components=2 -C extracted/$FILE/
			if [ -f extracted/$FILE/Logs/*var-log.tar.gz ]; then
				mkdir extracted/$FILE/Logs/varlogs/
				tar -xf extracted/$FILE/Logs/*var-log.tar.gz --strip-components=2 -C extracted/$FILE/Logs/varlogs
				rm -f extracted/$FILE/Logs/*var-log.tar.gz 
				if [[ $(find extracted/$FILE/Logs/varlogs/ -name "*.gz" | wc -c) -ne 0 ]]; then find extracted/$FILE/Logs/varlogs/ -name "*.gz" -print0 | xargs -0 gunzip; fi
			fi
			if [ -f extracted/$FILE/Logs/*var-adm.tar.gz ]; then
				mkdir extracted/$FILE/Logs/varadm/ 
				tar -xf extracted/$FILE/Logs/*var-adm.tar.gz --strip-components=2 -C extracted/$FILE/Logs/varadm 
				rm -f extracted/$FILE/Logs/*var-adm.tar.gz 
				if [[ $(find extracted/$FILE/Logs/varadm/ -name "*.gz" | wc -c) -ne 0 ]]; then find extracted/$FILE/Logs/varadm/ -name "*.gz" -print0 | xargs -0 gunzip; fi
			fi
			if [ -f extracted/$FILE/System_Info/*etc-key-files.tar.gz ]; then
				mkdir extracted/$FILE/System_Info/etc-key-files/
				tar -xf extracted/$FILE/System_Info/*etc-key-files.tar.gz --strip-components=1 -C extracted/$FILE/System_Info/etc-key-files
				rm -f extracted/$FILE/System_Info/*etc-key-files.tar.gz
			fi
        	if [ -f extracted/$FILE/System_Info/*etc-modified-files.tar.gz ]; then
				mkdir extracted/$FILE/System_Info/etc-modified-files/
				tar -xf extracted/$FILE/System_Info/*etc-modified-files.tar.gz --strip-components=1 -C extracted/$FILE/System_Info/etc-modified-files
				rm -f extracted/$FILE/System_Info/*etc-modified-files.tar.gz
			fi
			if [ -f extracted/$FILE/User_Files/*hidden-user-home-dir.tar.gz ]; then
				mkdir extracted/$FILE/User_Files/hidden-user-home-dir/ 
				tar -xf extracted/$FILE/User_Files/*hidden-user-home-dir.tar.gz -C extracted/$FILE/User_Files/hidden-user-home-dir
				rm -f extracted/$FILE/User_Files/*hidden-user-home-dir.tar.gz
				find extracted/$FILE/User_Files/hidden-user-home-dir/ -type f -print0 | xargs -0 rename 's/\.//g'
                if [ -d extracted/$FILE/User_Files/hidden-user-home-dir/home/ ]; then
			    	mv extracted/$FILE/User_Files/hidden-user-home-dir/home/* extracted/$FILE/User_Files/hidden-user-home-dir/
				    rm -rf extracted/$FILE/User_Files/hidden-user-home-dir/home/
                fi
			fi
			# If folder is empty there were no files in var/spool/cron/crontabs directory
			if [ -f extracted/$FILE/Persistence/*cron-folder.tar.gz ]; then
				mkdir extracted/$FILE/Persistence/crontabs/
				tar -xf extracted/$FILE/Persistence/*cron-folder.tar.gz --strip-components=4 -C extracted/$FILE/Persistence/crontabs
				rm -f extracted/$FILE/Persistence/*cron-folder.tar.gz
			fi
			if [ -f extracted/$FILE/Process_and_Network/*ssh-folders.tar.gz ]; then
				tar -xf extracted/$FILE/Process_and_Network/*ssh-folders.tar.gz -C extracted/$FILE/Process_and_Network/
				rm -f extracted/$FILE/Process_and_Network/*ssh-folders.tar.gz
				mv extracted/$FILE/Process_and_Network/home/* extracted/$FILE/Process_and_Network/
				rm -rf mv extracted/$FILE/Process_and_Network/home/
			fi
			chmod -R 777 extracted
			echo " Completed"
		fi
}

amiroot
for f in *.tar.gz; do (extract "$f"); done #for loop to search the directory for all the tar.gz files. Error suppresion not ideal
