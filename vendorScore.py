
from pip._vendor import requests
from bs4 import BeautifulSoup 
from datetime import datetime, timedelta,timezone
import json
import time
import argparse
import re
import warnings
import prettytable

global_table = prettytable.PrettyTable()
global_table.field_names = ["Source", "CVE", "Severity", "Score", "Vector", "ECM"]

def prettyTable(source, cve, sev, score, vector,ecm):
    #table = prettytable.PrettyTable()
    #table.field_names = ["Source","CVE", "Severity", "Score", "Vector", "ECM"]
    #table.add_row([source,cve, sev, score, vector,ecm])
    global_table.add_row([source, cve, sev, score, vector, ecm])
    #print(table)

def rhel_score_comparision(cve):
    #print(cve, type(cve))
    source = 'RedHat'
    url = 'https://access.redhat.com/hydra/rest/securitydata/cve/'+cve+'.json'
    response = requests.get(url)
    data = json.loads(response.content)
    try: 
        rh_severity = data['threat_severity']
        rh_score = data['cvss3']['cvss3_scoring_vector']
        rh_cvss = data['cvss3']['cvss3_base_score']
        prettyTable(source, cve, rh_severity, rh_cvss,rh_score,None)
        #print("""RedHat
              #Severity: {0}
              #CVSS: {1}
              #CVSS Vector: {2}
              #""".format(rh_severity, rh_cvss, rh_score))
        #print("RedHat Severity: " + rh_severity)
        return[cve,rh_severity,rh_score,rh_cvss]
    except Exception as e:
        #print('')
        #print("The RHEL data may not be available for " + cve) 
        prettyTable(source, cve, None, None, None, None)

def ubuntu(cve):
    source = 'Ubuntu'
    url = 'https://ubuntu.com/security/cves/'+cve+'.json'
    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.content)
        try: 
            ub_severity = data['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            ub_cvss = data['impact']['baseMetricV3']['cvssV3']['vectorString']
            ub_score = data['cvss3']
            priority = ubuntu_priority(cve)
            prettyTable(source, cve, priority, ub_score, ub_cvss, None)
            #print("""Ubuntu
                #Severity: {0}
                #CVSS: {1}
                #CVSS Vector: {2}
                #Priority {3}
                #""".format(ub_severity, ub_score,ub_cvss,priority))
            return[cve,ub_severity,ub_score,ub_cvss]
        except Exception as e:
            #print('')
            #print("The Ubuntu data may not be available for " + cve) 
            prettyTable(source, cve, None, None, None, None)
    else:
        prettyTable(source, cve, response.status_code, response.status_code, response.status_code, response.status_code)
        #print(""" Ubuntu  response code {0}""".format(response.status_code))

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
    source = 'Amazon Linux'
    amznURL = 'https://explore.alas.aws.amazon.com/' + cve + '.json'
    response = requests.get(amznURL)
    if response.status_code == 200:
        data = response.json()
        alasSev = data.get('severity')
        alasScore = data.get('scores')
        for item in alasScore:
            if item.get('source') == 'AMAZON_LINUX':
                amznScore = item.get('score')
                amznCVSS = item.get('vector')
                break
        prettyTable(source, cve, alasSev, amznScore, amznCVSS,None)
        #print(f"""Amazon Linux: 
    #Severity: {alasSev} 
    #Score: {amznScore} 
    #Vector: {amznCVSS}""")
    else:
        #print("The Amazon linux data may not be available for " + cve)
        prettyTable(source, cve, None, None, None, None)

def cisaADP(cve):
    source = 'CISA ADP'
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
        prettyTable(source, cve, response.status_code, response.status_code, response.status_code, response.status_code)
        #print("The CISA ADP data may not be available for " + cve)
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
                                    
                prettyTable(source, cve, adpSev, None, adpvector,ecm)
                #print("""CISA ADP
                #Severity: {0}
                #CVSS Vector: {1}
                #Exploitation: {2} 
                        #""".format(adpSev, adpvector,ecm))
            

        

if __name__ == "__main__":
    testInput = input("Are you running this  using a list instead of 1 cve? Press y if yes else n ").strip()
    if testInput == "y":
        cveList = ['CVE-2025-6595', 'CVE-2025-48379']
        for cve in cveList:
            #print(f"Vendor Score for {cve} \n")
            rhel_score_comparision(cve)
            ubuntu(cve)   
            exploreALAS(cve)
            cisaADP(cve)
            #print("\n")
        print(global_table)
    else:
        #parser = argparse.ArgumentParser(description='Generating triage template for CVEs.')
        #parser.add_argument("--cve", required=True, type=str, help='CVE ID to triage.')
        #args = parser.parse_args()
        cveInput = input("Enter CVE:").strip()
        rhel_score_comparision(str(cveInput))
        ubuntu(str(cveInput))   
        exploreALAS(str(cveInput))
        cisaADP(str(cveInput))
        print(global_table)

   
