import requests
import json

nvd_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

def get_cve_info(cveId):
    cve_info_list = []
    res = requests.get(nvd_url+cveId)
    cve_info = res.json()

    # if CVE ID does not exist, retrun empty list
    if 'result' not in cve_info:
        return cve_info_list  
        
    for cve_item in cve_info['result']['CVE_Items']:
        
        # get CVSSv2
        cvssv2_score = cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
        print(cvssv2_score)
        cve_info_list.append(cvssv2_score)
        
        # get CVSSv3
        cvssv3_score = cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
        print(cvssv3_score)
        cve_info_list.append(cvssv3_score)        
        
        # get CWE-ID
        for problemtype_data in cve_item['cve']['problemtype']['problemtype_data']:
            cwes = []
            for cwe in problemtype_data['description']:
                print(cwe['value'])
                cwes.append(cwe['value'])          
            cve_info_list.append(cwes)
                
        # get description about CVE
        for description_data in cve_item['cve']['description']['description_data']:
            print(description_data['value'])
            cve_info_list.append(description_data['value'])

    return cve_info_list
