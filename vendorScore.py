
from pip._vendor import requests
from bs4 import BeautifulSoup 
from datetime import datetime, timedelta,timezone
import json
import time
import argparse
import re
import warnings

def rhel_score_comparision(cve):
    url = 'https://access.redhat.com/hydra/rest/securitydata/cve/'+cve+'.json'
    response = requests.get(url)
    data = json.loads(response.content)
    try: 
        rh_severity = data['threat_severity']
        rh_score = data['cvss3']['cvss3_scoring_vector']
        rh_cvss = data['cvss3']['cvss3_base_score']
        print("""RedHat
              Severity: {0}
              CVSS: {1}
              CVSS Vector: {2}
              """.format(rh_severity, rh_cvss, rh_score))
        #print("RedHat Severity: " + rh_severity)
        return[cve,rh_severity,rh_score,rh_cvss]
    except Exception as e:
        #print('')
        print("The RHEL data may not be available for " + cve) 

def ubuntu(cve):
    url = 'https://ubuntu.com/security/cves/'+cve+'.json'
    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.content)
        try: 
            ub_severity = data['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            ub_cvss = data['impact']['baseMetricV3']['cvssV3']['vectorString']
            ub_score = data['cvss3']
            priority = ubuntu_priority(cve)
            print("""Ubuntu
                Severity: {0}
                CVSS: {1}
                CVSS Vector: {2}
                Priority {3}
                """.format(ub_severity, ub_score,ub_cvss,priority))
            return[cve,ub_severity,ub_score,ub_cvss]
        except Exception as e:
            #print('')
            print("The Ubuntu data may not be available for " + cve) 
    else:
        print(""" Ubuntu
              response code {0}""".format(response.status_code))

def ubuntu_priority(cve):
    url = 'https://ubuntu.com/security/cves/'+cve+'.json'
    response = requests.get(url)
    
    if response.status_code == 200:
        data = json.loads(response.content)
        try: 
            ub_priority = data['priority']
            return[ub_priority]
        except Exception as e:
            #print('')
            print("The Ubuntu data may not be available for " + cve) 
    else:
        print("response code {0}".format(response.status_code))

def newAmazon(cve):
    amznURL = 'https://alas.aws.amazon.com/cve/html/' + cve + '.html'
    response = requests.get(amznURL)
    try:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            soup = BeautifulSoup(response.content, 'html.parser')
            if any("XMLParsedAsHTMLWarning" in str(warn.message) for warn in w):
                soup = BeautifulSoup(response.content, 'xml')
        row = soup.find_all('td')
        for item in row:
            if 'Amazon Linux' in item.text:
                nextRow = item.find_next('td')
                if nextRow and 'CVSS' in nextRow.text:
                    cvssAMZN = item.find_next('a')
                    if cvssAMZN:
                        cvss_score = cvssAMZN.text.strip()
                        vector = cvssAMZN['href']
                        cvss_vector = vector.split('=')[1] if '=' in vector else vector
                        print("""Amazon 
Severity: {0}
Cvss_vector: {1} """.format(cvss_score,cvss_vector))
    except Exception as e:
        print("The Amazon linux data may not be available for " + cve)

def cisaADP(cve):
    adpSev = ''
    adpvector = ''
    cveYear = cve.split('-')[1]
    cveNum = cve.split('-')[-1]
    cveKey = cveNum[:2] 
    reg = r'^0\d$'
    if  len(cveNum)<5:
        cveKey = cveKey[:1]
    adpURL = 'https://raw.githubusercontent.com/cisagov/vulnrichment/refs/heads/develop/'+  cveYear +'/' + cveKey+'xxx/'+cve+'.json'
    #print(adpURL)
    response = requests.get(adpURL)
    if response.status_code != 200:
        print("The CISA ADP data may not be available for " + cve)
    else:
        content = json.loads(response.content)
        container = content.get('containers')
        adp = container.get('adp')
        for item in adp:
            metric = item.get('metrics')
            if metric:
                for i in metric:
                    if i and 'other' in i and 'content' in i['other'] and 'options' in i['other']['content']:
                        ecm = i['other']['content']['options']
                        break
        cna = container.get('cna').get('metrics')
        if cna:
            for j in cna:
            #print(j)
                v3 = j.get('cvssV3_1')
                if v3:
                        adpSev = v3.get('baseSeverity')
                        adpvector = v3.get('vectorString')
                else:
                    for val in adp:
                        metric = item.get('metrics')
                        if metric:
                            for comp in metric:
                                
                                if comp and 'cvssV3_1' in comp:
                                    adpSev = comp.get('cvssV3_1').get('baseSeverity')
                                    adpvector = comp.get('cvssV3_1').get('vectorString')
                                    
                
                print("""CISA ADP
                Severity: {0}
                CVSS Vector: {1}
                Exploitation: {2} 
                        """.format(adpSev, adpvector,ecm))
            
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generating triage template for CVEs.')
    parser.add_argument("--cve", required=True, type=str, help='CVE ID to triage.')
    args = parser.parse_args()
    rhel_score_comparision(args.cve)
    ubuntu(args.cve)   
    newAmazon(args.cve)
    cisaADP(args.cve)

   
