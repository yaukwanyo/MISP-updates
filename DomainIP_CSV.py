import json
import base64
import datetime
import csv
import io

misperrors = {'error': 'Error'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Hannah Ward',
              'description': 'Export domain/ip scan results in csv format',
              'module-type': ['export']}


fieldmap = {
    "domain": "Domains/IPs",
    "hostname": "Domain/IPs",
    "ip-src": "Domain/IPs",
    "ip-dst": "Domain/IPs",
    "url": "Domain/IPs"
}

mispattributes = {'input':list(fieldmap.keys())}
outputFileExtension = "csv"
responseType = "application/txt"

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    print(request)
    response = io.StringIO()

    # Define field names
    writer = csv.DictWriter(response, fieldnames=["Type", "Value", "Virustotal Detection Ratio", "Quttera.com", "Sucuri",  "Port status"])

    writer.writeheader()

    for event in request["data"]:
        for attribute in event["Attribute"]:

            # Write scan results to rows
            if attribute["type"] in mispattributes["input"]:
                writer.writerow({
                    "Type": fieldmap[attribute["type"]],
                    "Value": attribute["value"],
                    "Virustotal Detection Ratio": getvtResult(attribute["comment"]),
                    "Quttera.com": getQutteraResult(attribute["comment"]),
                    "Sucuri": getSucuriResult(attribute["comment"]),
                    "Port status": getsignal(attribute["comment"])
                })

    r = {"response":[], "data":str(base64.b64encode(bytes(response.getvalue(), 'utf-8')), 'utf-8')}
    return r

# Get starting index
def st(comment, keyword):
    diff = len(keyword)
    stPos = comment.find(keyword) + diff
    return stPos

# Retrieve yougetsignal results
def getsignal(comment):
    stPos = st(comment, "Port 80: ")
    endPos = comment.find(" Port 443")
    p80 = comment[stPos:endPos]
    stPos = st(comment, "Port 443: ")
    p443 = comment[stPos:]
    result = "Port 80: \r\n" + p80 + "\r\n\r\nPort 443: " + p443
    return result

# Retrieve Sucuri scan results
def getSucuriResult(comment):
    stPos = st(comment,"Status: ")
    endPos = comment.find(" Web Trust")
    status = comment[stPos:endPos]
    stPos = st(comment, "Web Trust: ")
    endPos = comment.find("Port Status")
    webTrust = comment[stPos:endPos]
    sucuri = "Status: \r\n" + status + "\r\n\r\nWeb Trust: \r\n" + webTrust
    return sucuri


# Retrieve Quttera scan results
def getQutteraResult(comment):
    stPos = st(comment, "Quttera Result: ")
    endPos = comment.find(" Sucuri") 
    quttera = comment[stPos:endPos]
    return quttera

# Retrieve virustotal scan results
def getvtResult(comment):
    stPos = st(comment, "tio: ")
    endPos = comment.find(" Quttera")
    vt = "'" + comment[stPos:endPos]
    return vt

def introspection():
  modulesetup = {}
  try:
        responseType
        modulesetup['responseType'] = responseType
  except NameError:
      pass
  try:
      userConfig
      modulesetup['userConfig'] = userConfig
  except NameError:
      pass
  try:
      outputFileExtension
      modulesetup['outputFileExtension'] = outputFileExtension
  except NameError:
      pass
  try:
      inputSource
      modulesetup['inputSource'] = inputSource
  except NameError:
      pass
  return modulesetup

def version():
    return moduleinfo