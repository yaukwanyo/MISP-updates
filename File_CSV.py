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

# config fields that your code expects from the site admin


fieldmap = {
    "md5": "File"
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
    writer = csv.DictWriter(response, fieldnames=["MD5", "Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"])

    writer.writeheader()

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:

                # Write scan results to rows
                writer.writerow({
                    "MD5": attribute["value"],
                    "Fortinet": Result(attribute["comment"],"Fortinet"),
                    "Kaspersky": Result(attribute["comment"],"Kaspersky"),
                    "McAfee": Result(attribute["comment"], "McAfee"),
                    "Symantec": Result(attribute["comment"], "Symantec"),
                    "TrendMicro": Result(attribute["comment"], "TrendMicro"),
                    "TrendMicro-Housecall": Result(attribute["comment"], "TrendMicro-Housecall")
                })                   
    r = {"response":[], "data":str(base64.b64encode(bytes(response.getvalue(), 'utf-8')), 'utf-8')}

    return r

# Retrieve scan results
def Result(comment, antivirus):
    diff = len(antivirus + " Scan Result: ")
    stPos = comment.find(antivirus + " Scan Result: ") + diff
    endPos = comment.find(" Update", stPos)
    result = comment[stPos:endPos]
    return result

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
    #moduleinfo['config'] = moduleconfig
    return moduleinfo