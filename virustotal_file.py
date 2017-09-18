import json
import requests
from requests import HTTPError
import base64
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException
import time
import pymisp as pm
from pymisp import PyMISP
from pymisp import MISPEvent
import argparse
from collections import OrderedDict
import socket

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url', 'hostname', 'domain', "ip-src", "ip-dst"],
                  'output': ['url', 'hostname', 'domain', 'ip-src', 'ip-dst']
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'SSKYAU@OGCIO',
              'description': 'Get Scan Results',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["VTapikey"]

def init(url,key):
    return PyMISP(url,key, False, 'json')

def handler(q=False):
    global limit
    if q is False:
        return False
	
    q = json.loads(q)
	
    key = q["config"]["VTapikey"]
	
    r = {"results": []}

    print (q)

    if 'md5' in q:
        ioc = q["md5"]
        ioc_type = "md5"
        r["results"] += vtAPIscan(q['md5'], key)

	
    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
  
    delete_mispAttribute(q,ioc)

    return r

def vtAPIscan(md5, key):

    r = []
    result = []

    params = {'resource': md5, 'apikey': key}
    headers = {'Accept-Encoding': "gzip, deflate", "User-Agent": "gzip, My Python requests library example client or username"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

    antivirusList = ["Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"]

    if response.text:
        json_response = response.json()
        #print (json_response)
        result = getScanResults(json_response, antivirusList)

    comment = ""

    for antivirus in antivirusList:
        comment += antivirus + " Result:  " + "".join(result[antivirus]) + " \n " + "Update:  " + "".join(result[antivirus + " Scan Date"]) + " \n "

    r.append({"types": ["md5"], "values": [md5], "comment": comment})

    return r

def getResults(scanReportDict, antivirus):
    if antivirus in scanReportDict:
        scanResultDictOfAntivirus = scanReportDict[antivirus]
        if "detected" in scanResultDictOfAntivirus:
            scanUpdate = ""
            if "update" in scanResultDictOfAntivirus:
                scanUpdate = scanResultDictOfAntivirus["update"]
            if (scanResultDictOfAntivirus['detected']):
                scanResult = ''
                if 'result' in scanResultDictOfAntivirus['result']:
                    scanResult = scanResultDictOfAntivirus['result']
                    return scanResult, scanUpdate
                return "Clean" , scanUpdate
    return "Not mentioned", "N/A"

def getScanResults(json_response, antivirusList):
    d = OrderedDict()

    if "scans" in json_response:
        scanReportDict = json_response["scans"]

        for antivirus in antivirusList:
            d[antivirus], d[antivirus + " Scan Date"] = getResults(scanReportDict, antivirus)
            
    else: 
        for antivirus in antivirusList:
            d[antivirus], d[antivirus + " Scan Date"] = "File not found on Virustotal"

    return d
	
def delete_mispAttribute(q, ioc):

    myMISPurl = 'http://192.168.56.50'
    myMISPkey = '2WGtsQVM8ThD72afNgwu8Dd9F2hPUBIcOPuMtJRE'
    misp = init(myMISPurl, myMISPkey)

    eid = q["event_id"]
    event = misp.get_event(eid)

    attrib = []

    # Get Dict of Attributes
    for k, v in event.items():
        if isinstance(v, dict):
            for inK, inV in v.items():
                if inK == "Attribute" and isinstance(inV, list):
                    
                    for value in inV:
                        if isinstance(value, dict):
                            attrib.append(value)
                            


    # Delete attribute
    for attribute in attrib:
        if ioc in attribute.values():
            print("Found attribute")
            for k,v in attribute.items():
                if k =="id":
                    
                    misp.delete_attribute(v)

    return ""
	
	
def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo