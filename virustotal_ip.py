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
moduleinfo = {'version': '1.0', 'author': 'SEC21',
              'description': 'Get Scan Results',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["MISPurl", "MISPkey"]

def init(url,key):
    return PyMISP(url,key, False, 'json')

def handler(q=False):
    global limit
	
    # Just in case we have no data
    if q is False:
        return False

    # Load up that JSON
    q = json.loads(q)

    MISPurl = q["config"]["MISPurl"]
    MISPkey = q["config"]["MISPkey"] 

    # The return value
    r = {"results": []}

    print (q)
	
    # If the attribute belongs to any of the following types, scan and save results as an new attribute
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

    # Remove the original attribute
    delete_mispAttribute(q,ioc, MISPurl, MISPkey)

    return r

def scanURL(ioc):
    vt = virustotal(ioc)
	
    toReturn = "Virustotal \r\nDetection Ratio: " + vt 
	
    return toReturn

# Setup the browser
def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    return driver		

	
# Get reanalyzed results from virustotal.com (API does not support the "Reanalyze" function)
def virustotal(url):
    driver = startBrowsing()
    driver.get("https://www.virustotal.com/en/#url")

    print("Scanning " + url + " on virustotal...")

    # Wait until input box appears
    try:
        url_input = WebDriverWait(driver, 60).until(
            EC.visibility_of_element_located((By.XPATH, "//input[@id='url']"))
        )
    except:
        return "N/A"

    # enter url
    url_input = driver.find_element_by_xpath("//input[@id='url']")
    url_input.send_keys(url)
	
    # Wait until scan button appears
    try:
        submit = WebDriverWait(driver, 20).until(
            EC.visibility_of_element_located((By.XPATH, "//button[@id='btn-scan-url']"))
        )
        submit.click()
    except:
        return "N/A"
    
    # Wait until reanalyse button appears
    try:
        reanalyze = WebDriverWait(driver, 30).until(
            EC.visibility_of_element_located((By.XPATH, "//a[@id='btn-url-reanalyse']"))
        )
    except TimeoutException:
        return ""
    
    reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')

    driver.get(reanalyze)

    print("Reanalyzing...")

    # Wait until reanalysed results appear
    try:
        element = WebDriverWait(driver, 60).until(
            EC.visibility_of_element_located((By.TAG_NAME, "td"))
        )
    except:
        return "N/A" 
   
    # Obtain results
    cells = driver.find_elements_by_tag_name("td")
    ratio = cells[3].text
	
    return ratio
	
# Remove possible symbols in URL
def cleanURL(url):
	
    url = str(url)
    url = url.replace("[","")
    url = url.replace("]","")

    return url

def delete_mispAttribute(q, ioc, MISPurl, MISPkey):

    myMISPurl = MISPurl
    myMISPkey = MISPkey
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
    return moduleinfo