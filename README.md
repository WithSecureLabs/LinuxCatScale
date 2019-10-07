# LinuxCatScale
Incident Response collection and processing scripts with automated reporting scripts

**Collection**

Download the project and run the collection script on infected hosts with sudo rights. The script will create a directory called "FSecure-out" in the working directory and should remove all artefacts after being compressed. This will leave a filename in the format of `FSecure-Username-Hostname-YYMMDD-HHMM.tar.gz` 
This should be collected and placed in your cases folder.

Once these are all aggregated you can run extract.sh to extract all the files and place them in a folder called "extracted".

`./extract.sh`

This will keep the original files so that you can reference them later if needs be.


**Parsing**


The stack is configured to collect data from the Docker-Project/extracted directory, if you would like to change this to another location
Navigate to the Docker/config folder and open "docker-compose.yml" in your favourite text editor. 
The most important fields to change would be the volumes under the logstash section. This essentially maps drives on your analysis machine to the various docker containers. An example configuration is as follows:

```
logstash:
    image: docker.elastic.co/logstash/logstash:7.1.1
    volumes:
      - /home/Forensicator/cases/linux-hunt/linux-collection-script-sans/Docker/config/pipeline/:/usr/share/logstash/pipeline/
      - /home/Forensicator/cases/linux-hunt/linux-collection-script-sans/extracted/:/logs/
    networks:
      - elktest
    links:
      - elasticsearch
    restart: always
    depends_on:
      - elasticsearch
```

This effectively takes whatever is in `/home/Forensicator/cases/linux-CatScale/Docker/config/pipeline/` and makes it available in the docker container at `/usr/share/logstash/pipeline/`

This project has predefined grok filters to ingest data into elastic, feel free to modify them as you need. 

The indexes are split into snap-\* indicating a snapshot of data taken at the time of running the script and varlog-\* which indicates data came from a log source

Once in the directory of the docker-compose.yml file run the following command:

*docker-compose -p CatScale-projectName up*

This will download the docker images specified in the docker-compose.yml file and configure your elk stack.

Once it has started up you should be able to reach kibana at *127.0.0.1:8090* (As per the .yml file). If you want to spin up multiple stacks at the same time, you will need to change this accordingly.

To view the newly imported data: click on the management/gear icon -> Index Patterns and select the index you would like to import. These have been exported and can be found under the kibana folder. Click on management/gear icon, Saved Objects, import and select "CatScale-index-patterns.ndjson" from the kibana folder. Initial searches, visualisations and dashboards can also be imported from this folder.


**Reporting**

The Analysis phase of the project makes use of the Sigma project.

https://github.com/Neo23x0/sigma

Investigators can also create their own rules which may be case specific. Let us know if you would like to contribute to the detection rules even further. 

Simply run the processer.py with Python3 and provide the path of the extracted data at the prompt. This will generate .tex files which can be used to import directly into a ShareLatex stack. Feel free to change the code to integrate with your own reporting tool.  

**Hunting** 

With initial findings from the dashboards and Analysis/Reporting tool investigators have a good starting point at looking at the data. Figure out what else may have happened on the hosts and expand your investigation accordingly. You can then include additional IOC's (which may be case specific) in the reporting script. 


**Disclaimer**

We are not devs, please excuse poor coding practices - if you have suggestions/improvements we would love to hear them!
