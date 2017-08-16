import json
import base64
import requests
import time
import os
from pyvirtualdisplay import Display
from pymisp.tools import stix
from collections import OrderedDict
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from socket import *

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.2', 'author': 'SK',
              'description': 'Import some stix stuff',
              'module-type': ['import']}

moduleconfig = ["VTapikey"]


def handler(q=False):
    # Just in case we have no data
    if q is False:
        return False

    #Get Virustotal API key
    key = request.get("config", {"VTapikey": ""})
    key = key["VTapikey"]   	
	
    # The return value
    r = OrderedDict()
    r = {'results': []}
    comment = ""
	
    # Load up that JSON
    q = json.loads(q)

    # It's b64 encoded, so decode that stuff
    package = base64.b64decode(q.get("data")).decode('utf-8')

    # If something really weird happened
    if not package:
        return json.dumps({"success": 0})

    pkg = stix.load_stix(package)
    for attrib in pkg.attributes:

        if "md5" in attrib.type:
            md5 = attrib.value
            
            VTAPIresult = vtAPIscan(md5,key)
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": VTAPIresult })
			    
        elif "url" in attrib.type or "ip-dst" in attrib.type or "domain" in attrib.type:
            url = attrib.value
		    vt = virustotal(url)
		    quttera = Quttera(url)
		    sucuri = Sucuri(url)
		    port80 = portScan(url, 80)
		    port443 = portScan(url, 443)
		    comment = CombineScans(vt,quttera,sucuri,port80,port443)
		    r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": comment })
			
        else:
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": " "})
    return r

def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    return driver
	
def portScan(url,portNo):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(2)
    result = s.connect_ex((url, portNo))
    if result == 0:
        status = "Open"
    else:
        status = "Close"
    s.close()
    return status

def CombineScans(vt, quttera, sucuri, port80, port443):
    toReturn = "Virustotal \r\nDetection Ratio: " + vt +\
               "Quttera \r\nResult: \r\n" + quttera +\
    		   sucuri +\
    		   "Port Status \r\nPort 80: " + port80 + " \r\nPort 443: " + port443 
    return toReturn
	
def Sucuri(url):

    driver = startBrowsing()
    driver.get("https://sitecheck.sucuri.net/results/" + url)

    print("Scanning " + url + " on Sucuri...")
    results = driver.find_elements_by_tag_name("td")

    #Get Status
    endPos = results[3].text.find('"', 2)
    status = results[3].text[:endPos]

    #Get Web Trust
    endPos = results[5].text.find('"', 2)
    webTrust = results[5].text[:endPos]

    toReturn = ""
    toReturn = "Sucuri \r\n Status: \r\n" + status + "\r\nWeb Trust: " + webTrust
	
    return toReturn
 
def Quttera(url):
    driver = startBrowsing()
    driver.get("http://quttera.com/sitescan/" + url)

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
        
def virustotal(url):
    driver = startBrowsing()
    driver.get("https://www.virustotal.com/en/#url")
    
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
    
    return ratio
	
def vtAPIscan(md5, key):

    result = OrderedDict()
    params = {'resource': md5, 'apikey': key}
    headers = {'Accept-Encoding': "gzip, deflate", "User-Agent": "gzip, My Python requests library example client or username"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

    countOftry = 1
    while not response.text:
        if countOftry<10:
            time.sleep(1)
            countOftry += 1
            print("Try virustotal file scan again")
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        else:
            return []

    print(response.text)
    
    antivirusList = ["Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"]

    if response.text:
        json_response = response.json()
            
        result = getScanResults(json_response, antivirusList)
	
    toReturn = ""
	
    for antivirus in antivirusList:
        if bool(result[antivirus])
            toReturn += "\r\n\r\n" + antivirus + " Scan Result:\r\n " + result[antivirus] + "Update:\r\n " + result[antivirus + " Scan Date"]
        else:
            toReturn += "\r\n\r\n" + antivirus + " Scan Result:\r\n File not found\r\n" + "Update:\r\n N/A"
    return toReturn

def getResults(scanReportDict, antivirus):
    for k,v in scanReportDict.items():
       if k == antivirus:
            for inK, inV in v.items():
                if inK == "result" and inV != "None":
                    scanResult = inV
                    detected = True
                elif inK == "update":
                    scanUpdate = inV
                elif inK == "detected" and inV == False:
                    detected = False
                    print("No Virus!!!!!")
            if detected == False:
                return "File not detected", scanUpdate
            else:
                return scanResult, scanUpdate
    return "Not mentioend", "N/A" 

def getScanResults(json_response, antivirusList):
    d = OrderedDict()

    if "scans" in json_response:
        scanReportDict = json_response["scans"]
        print("got results!!:D")

        for antivirus in antivirusList:
            d[antivirus], d[antivirus + " Scan Date"] = getResults(scanReportDict, antivirus)

    return d


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo