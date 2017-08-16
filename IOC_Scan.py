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
import time
import pymisp as pm
from pymisp import PyMISP
from pymisp import MISPEvent
import argparse
from collections import OrderedDict

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url', 'hostname', 'domain', "ip-src", "ip-dst", "md5"],
                  'output': ['url', 'hostname', 'domain', 'ip-src', 'ip-dst', 'md5']
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
		
    if 'md5' in q:
        ioc = q["md5"]
        ioc_type = "md5"
        r["results"] += vtAPIscan(q['md5'], key)

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
    ratio = virustotal(ioc)
    quttera = quttera(ioc)
	sucuri = sucuri(ioc)
    port80 = portScan(ioc, p80)
    port443 = portScan(ioc, p443)
	
    toReturn = "Virustotal \r\nDetection Ratio: " + vt +\
               " \r\nQuttera \r\nResult: \r\n" + quttera +\
               sucuri +\
               " \r\nPort Status \r\nPort 80: " + port80 + " \r\nPort 443: " + port443 
    return toReturn
    
def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    return driver

def portScan(url,portNo):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(2)
    try:
        result = TCPsock.connect((url, portNo))
        if result == 0:
            status = "Open"
        else: status = "Close"
    except:
        status = "Invalid URL"
    return status
	
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
                    print("Hello", inV)
                    for value in inV:
                        if isinstance(value, dict):
                            attrib.append(value)
                            


    # Delete attribute
    for attribute in attrib:
        if ioc in attribute.values():
            print("Found attribute!")
            for k,v in attribute.items():
                if k =="id":
                    print(k,v)
                    misp.delete_attribute(v)

    return ""


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
        print (json_response)
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
                return "File not detected" , scanUpdate
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


def cleanURL(url):
	
    url = str(url)
    url = url.replace("[","")
    url = url.replace("]","")

    return url

def Sucuri(url):

    driver = startBrowsing()
    driver.get("https://sitecheck.sucuri.net/results/" + url)

    print("Scanning " + url + " on Sucuri...")
    results = driver.find_elements_by_tag_name("td")

    try:
        #Get status
        endPos = results[3].text.find('"', 2)
        status = results[3].text[:endPos]

        #Get Web Trust
        endPos = results[5].text.find('"', 2)
        webTrust = results[5].text[:endPos]
        if ":" in webTrust:
            endPos = webTrust.find(":", 2)
            webTrust = webTrust[:endPos]

    except:
        status = "Invalid URL"
        webTrust = "Invalid URL"

    toReturn = ""
    toReturn = "Sucuri \r\n Status: \r\n" + status + " \r\nWeb Trust: " + webTrust + " \r\n"
	
    return toReturn
	
def Quttera(url):
    driver = startBrowsing()
    driver.get("http://quttera.com/sitescan/" + url)

    print("Scanning " + url + " on Quttera...")
	
    try:
        complete = WebDriverWait(driver, 60).until(
            EC.visibility_of_element_located((By.XPATH, "//div[@id='ResultSummary']"))
        )
    except:
        try:
            malicious = driver.find_element_by_xpath("//div[@class='alert alert-m']").text
        except:
            result = "Unreachable"
            return result

        if "Malicious" in malicious:
            result = malicious
            return result
        '''
        else: 
            result = "Unreachable"
        '''
    summary = driver.find_element_by_xpath("//div[@id='ResultSummary']")
    scanResult = summary.find_elements_by_tag_name("h4")

    status = str(scanResult[0].text)

    print (isinstance(status, str))
    print (status)

    if "No Malware Detected" in status:
        result = "Clean"
    elif "Potentially Suspicious" in status:
        result = "Potentially Suspicious"
    elif "Malicious" in status:
        result = "Malicious"
    else: 
        result = ""
		
    return result		
	
def virustotal(url,type):
    driver = startBrowsing()
    driver.get("https://www.virustotal.com/en/#url")

    print("Scanning " + url + " on virustotal...")
	
    url_input = WebDriverWait(driver, 60).until(
        EC.visibility_of_element_located((By.XPATH, "//input[@id='url']"))
    )

    url_input = driver.find_element_by_xpath("//input[@id='url']")
    url_input.send_keys(url)
    submit = driver.find_element_by_xpath("//button[@id='btn-scan-url']")
    submit.click()
    
    print("submitted url!")

    try:
        reanalyze = WebDriverWait(driver, 300).until(
            EC.visibility_of_element_located((By.XPATH, "//a[@id='btn-url-reanalyse']"))
        )
    except TimeoutException:
        return ""
    
    reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')

    driver.get(reanalyze)

    print("Now reanalyzingggggg")
    element = WebDriverWait(driver, 6000).until(
        EC.visibility_of_element_located((By.TAG_NAME, "td"))
    )
    
    cells = driver.find_elements_by_tag_name("td")
    ratio = cells[3].text
	
    comment = "Virustotal \r\nDetection Ratio: " + ratio
	
    r.append({'types': [type], "values": [url], "comment": comment})
	
    return result
	
	
def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo