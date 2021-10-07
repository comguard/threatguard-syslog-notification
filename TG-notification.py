import xml.etree.ElementTree as ET
import urllib
import urllib.request as urllib2
import logging
import logging.handlers
import sys
import getopt
import os
from datetime import datetime

url = ''
server = ''
port = 0

#Get the paramateres
def getParameters(argv):
    global url, server, port
    try:
        opts, args = getopt.getopt(argv,"hu:s:p:",["url=","server=","port="])
    except getopt.GetoptError:
        print('TG-notification-3.py -u <threatguard_url> -s <server_IP> -p <server_port>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('TG-notification-3.py -u <threatguard_url> -s <server_IP> -p <server_port>')
            sys.exit()
        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-s", "--server"):
            server = arg
        elif opt in ("-p", "--port"):
            port = int(arg)

getParameters(sys.argv[1:])

#Parse TG export and creat message
s = urllib2.urlopen(url)
contents = s.read()
file = open("./TG-export.xml", 'wb')
file.write(contents)
file.close()

#Prepare files
old_IDs = []
old_Dates = []
logs = ""

if (os.path.isfile("./Export-old.xml") and not (os.stat("./Export-old.xml").st_size == 0)):
    oldRoot = ET.parse('./Export-old.xml').getroot()
    for threat in oldRoot.findall('THREAT'):
        old_IDs.append(threat.find('ID').text)
        old_Dates.append(threat.find('UPDATED_AT').text)
else:    
    fileold = open("./Export-old.xml", 'a+')
    fileold.close()

root = ET.parse('./TG-export.xml').getroot()

#Create syslog
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sys_log_handler = logging.handlers.SysLogHandler(address=(server, port))
logger.addHandler(sys_log_handler)

#Creating message
endOfStr = '" '

for threat in root.findall('THREAT'):
    newID = threat.find('ID').text
    isNew = True
    for ID in old_IDs:
        index = old_IDs.index(ID)
        if (newID == ID and threat.find('UPDATED_AT').text == old_Dates[index]):
            isNew = False
    if (isNew):
        newThreat = ''
        newThreat += 'ID="'
        newThreat += threat.find('ID').text
        newThreat += endOfStr
        newThreat += 'NAME="'
        newThreat += threat.find('NAME').text
        newThreat += endOfStr
        type = ''
        for types in threat.findall('TYPES'):
            more = False
            for oneEl in types.findall('TYPE'):
                if(more):
                    type += ', ' + oneEl.text
                else:
                    type += oneEl.text
                more = True
        newThreat += 'TYPE="'
        newThreat += type
        newThreat += endOfStr
        newThreat += 'RELEVANCE="'
        newThreat += threat.find('RELEVANCE').text
        newThreat += endOfStr
        cvss = threat.find('CVSS').text
        if not (cvss is None):
            newThreat += 'CVSS="'
            newThreat += cvss
            newThreat += endOfStr
        cve = threat.find('CVE_LINK').text
        if not (cve is None):
            newThreat += 'CVE_LINK="'
            newThreat += cve.replace("\n", "|")
            newThreat += endOfStr
        cvePublished = threat.find('CVE_PUBLISHED').text
        if not (cvePublished is None):
            newThreat += 'CVE_PUBLISHED="'
            newThreat += cvePublished
            newThreat += endOfStr
        newThreat += 'SHORT_DESCRIPTION="'
        newThreat += threat.find('DESC_SHORT').text
        newThreat += endOfStr
        newThreat += 'THREAT_LINK="'
        newThreat += threat.find('THREAT_LINK').text
        newThreat += '"'

        #print(newThreat)
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        log = dt_string + ' to ' + server + ': ' + newThreat + '\n'
        logs = logs + log

        # Send syslog
        logger.info(newThreat)

with open("logs.txt", "a") as text_file:
    print("{}".format(logs), file=text_file)

oldFile = open("./Export-old.xml", 'wb')
oldFile.write(contents)
oldFile.close()
