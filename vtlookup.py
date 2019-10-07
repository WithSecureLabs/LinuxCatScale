#This is proof of concept code that queries the hashes from the elk stack and checks for matches on virustotal.
# In future this will ammed the elastic document to include the number and type of hits.


from elasticsearch import Elasticsearch
import requests
from virus_total_apis import PublicApi as VirusTotalPublicApi
import json


API_KEY = '---Enter Key Here---'

# Connect to the elastic cluster
es=Elasticsearch([{'host':'localhost','port':9200}])

searches = es.search(index = 'snap-process-hashes*', size=1000)

#Initiate vt
vt = VirusTotalPublicApi(API_KEY)

data = json.dumps(searches)
data = searches.get('hits')

md5="07a9f658b4ae03a2a286ec040298cac9"


vtresult=vt.get_file_report(md5)
#print(json.dumps(vtresult["results"], sort_keys=False, indent=4))


for p in data['hits']:
     data=p['_source']
     #print(data)
     md5=data.get('md5sum', None)

     if (len(md5) >= 30):
        try:
            vtresult=vt.get_file_report(md5)
            if( json.dumps(vtresult["results"]["response_code"]) == '1'):
                print("success")
                print(json.dumps(vtresult["results"]['positives'], sort_keys=False, indent=4))
                if ((int)(json.dumps(vtresult["results"]['positives'], sort_keys=False, indent=4)) > 1):
                    print(json.dumps(vtresult["results"], sort_keys=False, indent=4))                
            else:
                print("Unknown file hash" + md5)
        except:
            print("An error has occured")
            print(md5)