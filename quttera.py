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
#moduleconfig = ["VTapikey"]

def init(url,key):
    return PyMISP(url,key, False, 'json')

def handler(q=False):
    global limit
    if q is False:
        return False
	
    q = json.loads(q)
	
    #key = q["config"]["VTapikey"]

    r = {"results": []}

    print (q)
	
    if "ip-src" in q:
        ioc = q["ip-src"]
        ioc_type = "ip-src"
        url = cleanURL(q["ip-src"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
        
		
    if "ip-dst" in q: 
        ioc = q["ip-dst"]
        ioc_type = "ip-dst"
        url = cleanURL(q["ip-dst"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "domain" in q: 
        ioc = q["domain"]
        ioc_type = "domain"
        url = cleanURL(q["domain"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "hostname" in q:
        ioc = q["hostname"]
        ioc_type = "hostname"
        url = cleanURL(q["hostname"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})

    if "url" in q:
        ioc = q["url"]
        ioc_type = "url"
        url = cleanURL(q["url"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
	
    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
  
    delete_mispAttribute(q,ioc)

    return r

def scanURL(ioc):
    quttera = Quttera(ioc)
	
    toReturn = " \r\nQuttera \r\nResult: \r\n" + quttera
    return toReturn
    
def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    return driver
	
def Quttera(url):

    status = "N/A"
    driver = startBrowsing()
    print("Scanning " + url + " on Quttera...")

    try:
        driver.get("https://quttera.com/detailed_report/" + url)
    except TimeoutException:
        print("Scan failed")
        return status

    results = driver.find_elements_by_xpath("//div[@class='panel-heading']")
   
    for result in results:
        if "No Malware" in result.text:
            status = "Clean"
            break
        elif "Potentially Suspicious" in result.text:
            status = "Potentially Suspicious"
            break
        elif "Malicious" in result.text:
            status = "Malicious"
            break
        else:
            status = "Unreachable"
             
    print(status)
    
    return status		
	
def cleanURL(url):
	
    url = str(url)
    url = url.replace("[","")
    url = url.replace("]","")

    return url

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
    #moduleinfo['config'] = moduleconfig
    return moduleinfo