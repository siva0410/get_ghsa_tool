import requests
import json

nvd_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

def get_cve_info(cveId_list):
    cve_info_list = []
    for cveId in cveId_list:
        cve_info = []
        
        # if CVE ID does not exist, append empty list
        if cveId is None:
            cve_info_list.append([0,0,"",""])
            continue
        
        res = requests.get(nvd_url+cveId)
        cve_json = res.json()

        # if CVE ID infomation does not exist, append empty list
        if 'result' not in cve_json:
            cve_info_list.append([0,0,"",""])
            continue  
        
        for cve_item in cve_json['result']['CVE_Items']:
        
            # get CVSSv2
            cvssv2_score = cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
            print(cvssv2_score)
            if not cvssv2_score:
                cvssv2_score = 0
            cve_info.append(cvssv2_score)
        
            # get CVSSv3
            cvssv3_score = cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
            print(cvssv3_score)
            if not cvssv3_score:
                cvssv3_score = 0
            cve_info.append(cvssv3_score)                
                
            # get description about CVE
            for description_data in cve_item['cve']['description']['description_data']:
                print(description_data['value'])
                if not description_data['value']:
                    cve_info.append("")
                else:
                    cve_info.append(description_data['value'])

            # get CWE-ID
            for problemtype_data in cve_item['cve']['problemtype']['problemtype_data']:
                cwes = []
                for cwe in problemtype_data['description']:
                    print(cwe['value'])
                    cwes.append(cwe['value'])
                if not cwes:
                    cwes.append("")
                cve_info.append(cwes)

        cve_info_list.append(cve_info)

    return cve_info_list
