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


## What does it collect?

This script will produce output and archive. Currently most up to date what it collects is covered in the blog post here: https://labs.f-secure.com/tools/cat-scale-linux-incident-response-collection/

## Disclaimer

Note that the script will likely alter artefacts on endpoints. Care should be taken when using the script. This is not meant to take forensically sound disk images of the remote endpoints.


## Tested OSes

- Ubuntu 16.4
- Centos
- Mint
- Solaris 11.4
