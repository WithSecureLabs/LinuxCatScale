#!/bin/bash
# This script is used to extract artefacts gathered from the F-Secure Consulting Linux Collection scripts and change the file permissions so that Docker can read the collected files
# It also combines the file system metadata into a single file
set -e
#set -x # uncomment to debug

TAR=`which tar`
FIND=`which find`
RENAME=`which rename`



extract() #This is where all the dirty work happens
{

    # strip leading dir and extension 
    TEMP1=`echo $1 | cut -d'.' -f 1`
    FILE=`echo $TEMP1 | cut -d'/' -f 2`
    echo -n $FILE

    mkdir -p extracted/$FILE
    $TAR -m -zxf $1 --strip-components=2 -C extracted/$FILE/

    mkdir -p extracted/$FILE/varlogs/
    mkdir -p extracted/$FILE/bash_history/
    mkdir -p extracted/$FILE/viminfo/
    mkdir -p extracted/$FILE/bash_profile/
    mkdir -p extracted/$FILE/bash_rc/

    $TAR -m -zxf extracted/$FILE/*var_logs.tar.gz --strip-components=2 -C extracted/$FILE/varlogs/
    rm extracted/$FILE/*var_logs.tar.gz
  
    [ -f extracted/$FILE/varlogs/auth.log.1.gz ] && gunzip extracted/$FILE/varlogs/auth.log.*.gz
    [ -f extracted/$FILE/varlogs/syslog.1.gz ] && gunzip extracted/$FILE/varlogs/syslog.*.gz   
    [ -f extracted/$FILE/*bash_history.tar ] && $TAR -m -xf extracted/$FILE/*bash_history.tar -C extracted/$FILE/bash_history/ && rm extracted/$FILE/*bash_history.tar
    [ -f extracted/$FILE/*bash_profile.tar ] && $TAR -m -xf extracted/$FILE/*bash_profile.tar -C extracted/$FILE/bash_profile/ && rm extracted/$FILE/*bash_profile.tar
    [ -f extracted/$FILE/*bashrc.tar ] && $TAR -m -xf extracted/$FILE/*bashrc.tar -C extracted/$FILE/bash_rc/ && rm extracted/$FILE/*bashrc.tar
    [ -f extracted/$FILE/*viminfo.tar ] && $TAR -m -xf extracted/$FILE/*viminfo.tar -C extracted/$FILE/viminfo/ && rm extracted/$FILE/*viminfo.tar
    #Find and remove leading . from bash history files
    $FIND extracted/$FILE/bash_history/ -type f -exec $RENAME 's/\.//g' {} \;
    #Find and remove leading . from viminfo files
    $FIND extracted/$FILE/viminfo/ -type f -exec $RENAME 's/\.//g' {} \;
    #Change permissions on all files so that docker can read everything 
    chmod -R 777 extracted
    #Parsing for timeline
    cat extracted/$FILE/*-timeline >> extracted/$FILE/full-timeline.csv
    sed -i '1s/^/Access Date,Access Time,Modify Date,Modify Time,Change Date,Change Time,Permissions,UID,Username,GID,Groupname,Size,File\n/' extracted/$FILE/full-timeline.csv
    echo " completed"
}

for f in *.tar.gz; do (extract "$f"); done #for loop to search the directory for all the tar.gz files
