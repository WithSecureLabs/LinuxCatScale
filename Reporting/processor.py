#!/usr/bin/env python3
import os
import subprocess

#***************************
#Class Definiition for running shell commands. Usage: variable = Command("bash command you want to run").run()

class Command(object):
    """Run a command and capture it's output string, error string and exit status"""
    def __init__(self, command):
        self.command = command 
    def run(self, shell=True):
        import subprocess as sp
        process = sp.Popen(self.command, shell = shell, stdout = sp.PIPE, stderr = sp.PIPE)
        self.pid = process.pid
        self.output, self.error = process.communicate()
        self.failed = process.returncode
        return self
    @property
    def returncode(self):
        return self.failed
#***************************
#Find Function Definitions:

#Find file by name
def find_file(name, path):
    result = []
    for root, dirs, files in os.walk(path):
        if name in files:
            result.append(os.path.join(root, name))
    return result

#Create report File
def create_file(hostname):
    filename="{}-report.tex".format(str(hostname))
    if os.path.exists(filename):
        os.remove(filename)

    f=open(filename,"w")
    return(f,filename)


#Analysis on files
def analyse_file(alert,files,matchstr,bash=False):
    for f in files:
        with open(f, 'r') as file:
            #get and match lines from list    	
            lines=file.readlines()
            for line in lines:
                for match in matchstr:
                    if match in line:
                        alert_finding(alert,str(f),line,bash)	

#Alert on finding
def alert_finding(type,f,line,bash=False):
    if bash == True:
        print("\\begin{lstlisting} \n", file=fil)
        print("Alert: Bash History has been cleared\nFile: {}\nCommand executed: {}".format(f,line), file=fil)
        print("\end(lstlisting} \n", file=fil)
    else:
        print("\\begin{lstlisting} \n", file=fil)
        print("Alert: {} found in file: \n{}\nCommand Executed: {}".format(type,f,line), file=fil)
        print("\end{lstlisting} \n", file=fil)
#*********************
extracted_dir=input("Please provide path to extracted directory, for example: /home/analyst/Downloads/extracted/ \n >> ")

hostnames=os.listdir(extracted_dir)

for host in hostnames:
    fil, report_name = create_file(host)

    print("Analysing host: {}\n".format(host))

    #GENERAL INFO:
    print("Collecting General Information from host: {} \n".format(host))
    #Gathering Users from host:
    users_cmd=('cat {}{}/*-passwd.txt | grep -v "nologin" | cut -d":" -f1'.format(extracted_dir,host))
    get_users = subprocess.check_output(users_cmd, shell=True)
    lst = []

    for char in get_users.decode():
        lst.append(char)
    
    user_list=''.join(lst).split('\n')
    
    #Printing users to file
    print("\hii{{Analysis of host {}}} \n".format(host),file=fil)
    print("\hiv{Users on host:} \n \\begin{lstlisting}", file=fil)
    for user in user_list:
        print(user,file=fil)
    print("\end{lstlisting}",file=fil)
    #GENERAL: Process lastlog - last logged in users:
     
    last_cmd = ('cat {}{}/*-lastlog.txt | grep -v \'Never logged in\''.format(extracted_dir,host))
    get_last = subprocess.check_output(last_cmd, shell=True)

    print("\hiii{User login summary} \n", file=fil)
    print("\\begin{lstlisting}",file=fil)
    print(get_last.decode(),file=fil)
    print("\end{lstlisting}",file=fil)
    #***************************************************

    #GENERAL: Process lastbad - Failed SSH login

    last_bad_cmd = ('cat {}{}/*-lastbad.txt'.format(extracted_dir,host))
    get_last_bad = subprocess.check_output(last_bad_cmd, shell=True)
    print("\hiii{Last failed SSH logons} \n \\begin{lstlisting}", file=fil)
    print(get_last_bad.decode(),file=fil)
    print("\end{lstlisting}",file=fil)
    #GENERAL: Searching for newly created users:

    log_path = "{}{}/varlogs/".format(extracted_dir,host)
    new_users_cmd = ('cat {}auth.log | grep useradd | grep -v failed'.format(log_path))

    try:
        get_added_users = subprocess.check_output(new_users_cmd, shell=True)
        print("hiii{New Users Added} \n \\begin{lstlisting}",file=fil)
        print(get_added_users.decode(),file=fil)
        print("\end{lstlisting}",file=fil)
    except: #need to fix this 
        print("No new users found. \n \\begin{lstlisting}",file=fil)
        print("\end{lstlisting}",file=fil)
        
    

    print("Processing Bash History for host: {}\n".format(host))
    
    #BASH HISTORY: Search for clearing of bash history
    #Define bash_history clearing commands
    #Reference: https://github.com/Neo23x0/sigma/blob/master/rules/linux/lnx_shell_clear_cmd_history.yml
    matchstr=['rm *bash_history','echo "" > *bash_history','cat /dev/null > *bash_history', 'ln -sf /dev/null *bash_history','truncate -s0 *bash_history','export HISTFILESIZE=0','history -c']
    
    #Find all Bash_history files from current path:
    bashfiles=find_file(".bash_history","{}{}/".format(extracted_dir,host))
    print("\hiii{Bash History Analysis} \n", file=fil)     
    analyse_file("Bash History Cleared",bashfiles,matchstr,True)
    ##=======================================    		
    ##BASH HISTORY: Searching for suspicious shell commands: 
    ##Reference: https://github.com/Neo23x0/sigma/blob/master/rules/linux/lnx_shell_susp_commands.yml
    
    shellstr=['wget * - http* | perl','wget * - http* | sh','wget * - http* | bash','python -m SimpleHTTPServer','-m http.server','import pty; pty.spawn*','socat exec:*','socat -O /tmp/*','socat tcp-connect*','*echo binary >>*','*wget *; chmod +x*','*wget *; chmod 777 *','*cd /tmp || cd /var/run || cd /mnt*','*stop;service iptables stop;*','*stop;SuSEfirewall2 stop;*','chmod 777 2020*','*>>/etc/rc.local','*base64 -d /tmp/*','* | base64 -d *','*/chmod u+s *','*chmod +s /tmp/*','*chmod u+s /tmp/*','* /tmp/haxhax*','* /tmp/ns_sploit*','nc -l -p *','cp /bin/ksh *','cp /bin/sh *','* /tmp/*.b64 *','*/tmp/ysocereal.jar*','*/tmp/x *','*; chmod +x /tmp/*','*;chmod +x /tmp/*']
    
    #Open the files found
    analyse_file("Suspicious Shell Command",bashfiles,shellstr)

    #================================================
    ##BASH HISTORY: Searching for potential Reverse Shell exploits
    #
    revstr=['BEGIN {s = "/inet/tcp/0/','bash -i >& /dev/tcp/','bash -i >& /dev/udp/','sh -i >$ /dev/udp/','sh -i >$ /dev/tcp/','&& while read line 0<&5; do','/bin/bash -c exec 5<>/dev/tcp/','/bin/bash -c exec 5<>/dev/udp/','nc -e /bin/sh ','/bin/sh | nc','rm -f backpipe; mknod /tmp/backpipe p && nc ',';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))',';STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;','/bin/sh -i <&3 >&3 2>&3','uname -a; w; id; /bin/bash -i','$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()};',";os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv('HISTFILE','/dev/null');",'.to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)',';while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print',"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:",'rm -f /tmp/p; mknod /tmp/p p &&',' | /bin/bash | telnet ',',echo=0,raw tcp-listen:','nc -lvvp','xterm -display 1']
    #
    analyse_file("Potential reverse shell exploit",bashfiles,revstr)
    #================================================
    #BASH HISTORY: Searching for possible enumeration attempts: 
    #Reference:https://github.com/Neo23x0/sigma/blob/master/rules/linux/lnx_shell_priv_esc_prep.yml
    
    #Define suspicious enumeration strings:
    enumstr=['cat /etc/issue','cat /etc/*-release','cat /proc/version','uname -a','uname -mrs','rpm -q kernel','dmesg | grep Linux','ls /boot | grep vmlinuz-','cat /etc/profile','cat /etc/bashrc','cat ~/.bash_profile','cat ~/.bashrc','cat ~/.bash_logout','ps -aux | grep root','ps -ef | grep root','crontab -l','cat /etc/cron*','cat /etc/cron.allow','cat /etc/cron.deny','cat /etc/crontab','grep -i user *','grep -i pass *','ifconfig','cat /etc/network/interfaces','cat /etc/sysconfig/network','cat /etc/resolv.conf','cat /etc/networks','iptables -L','lsof -i','netstat -antup','netstat -antpx','netstat -tulpn','arp -e','route','cat /etc/passwd','cat /etc/group','cat /etc/shadow'] 
    analyse_file("Potential enumeration activity",bashfiles,enumstr)
    ##================================================
    print("Analyzing Log Files for host {}\n".format(host))
    
    print("\hiii{Log File Analysis} \n", file=fil)
    #LOGFILE ANALYSIS: Searching for shellshock in logs
    
      
    #Using Command Function, grep for shellshock pattern:
    grep_com = 'grep -e "() {{" -r {}*'.format(str(log_path)) 
    execute_grep = Command(grep_com).run()
    
    print("Potential Evidence of shellshock found in logfile: \n ", file=fil)
    print(execute_grep.output.decode(),file=fil)
    #===============================================
    

    #BASH HISTORY: Searching for potential alteration of user environment for persistence:
    #Reference: https://github.com/Neo23x0/sigma/blob/master/rules/linux/auditd/lnx_auditd_alter_bash_profile.yml

    #Define suspicious enumeration strings:
    bashstr1=['/home/*/.bashrc','/home/*/.bash_profile','/home/*/.profile','/etc/profile','/etc/shells','/etc/bashrc','/etc/csh.cshrc','/etc/csh.login']
    print("\\begin{lstlisting}", file=fil)
    analyse_file("Suspicous editing of .bash_profile and .bashrc",bashfiles,bashstr1)
    print("\end{lstlisting}", file=fil)
    ##================================================
  
    #LOGFILE ANALYSIS: Searching for failed password logins / brute force attempts
    
    #Define SED commands to search through logs matched by grep.
    
    sed_ip="sed -n 's/.* from \([^ ]*\).*/\\1/p'"
    sed_user="sed -n 's/.* user \([^ ]*\).*/\\1/p'"
    
    #Define Grep commands 
    failed_grep_ip_sed = 'grep -ai "failed password" {}auth.log*| {} | sort | uniq -c'.format(str(log_path),sed_ip) 
    failed_grep_user_sed = 'grep -ai "failed password" {}auth.log*| {} | sort | uniq -c'.format(str(log_path),sed_user) 
    failed_grep_ip = 'grep -ai "failed password" {}auth.log*'.format(str(log_path))
    
    #Execute defined commands
    
    proc_ip_count = subprocess.check_output(failed_grep_ip_sed, shell=True)
    proc_user_count = subprocess.check_output(failed_grep_user_sed, shell=True)

    #Display output
    if not proc_ip_count == "":
        print("\\begin{lstlisting}",file=fil)
        print("\hiii{Failed Password Authentication Attempts} \n", file=fil)
        print("\hiv{Source IP from failed attempts} \n", file=fil)
        print("Count: Source\_IP: \n", file=fil)
        print(proc_ip_count.decode(), file=fil)
        print("\end{lstlisting}",file=fil)
    else:
        print("No failed authentication attempts found", file=fil)

    if not proc_user_count == " ":
        print("\\begin{lstlisting}",file=fil)
        print("\hiv{User Name count from failed attempts} \n", file=fil)    
        print("Count: UserName:", file=fil)
        print(proc_user_count.decode(), file=fil)
        print("\end{lstlisting}",file=fil)
    else:
        continue

    #=============================================
    fil.close()
    print("************************************************************\n")
    print("Done, report generated for host {} in file {}\n".format(host,report_name))
    print("************************************************************\n")
