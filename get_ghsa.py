import json
import requests
import re
import time
import csv

from bs4 import BeautifulSoup

from config import *

repo_url = "https://github.com/"+USER+"/"+REPOSITORY
ghsa_base_url = repo_url+"/security/advisories"
ghsa_list = []
cves = []

def get_ghsa_info():

    for ghsa in ghsa_list:
        ghsa_info = [ghsa]
        ghsa_url = ghsa_base_url+"/"+ghsa
        res = requests.get(ghsa_url)
        time.sleep(SLEEP)
        print("[*]Search", ghsa_url)
        print("[*]Status Code", res.status_code)
        
        soup = BeautifulSoup(res.text, "html.parser")

        div_texts = [div.get_text(strip=True) for div in soup.find_all('div')]
        
        # Affected version
        exist_affected_version = False
        affected_version_pattern = re.compile(r"<=? ([0-9]+.[0-9]+[.0-9]*)|All versions")
        for div_text in div_texts:
            affected_version_info = affected_version_pattern.search(div_text)
            if affected_version_info:
                exist_affected_version = True
                if affected_version_info.group(1) not in ghsa_info:
                    ghsa_info.append(affected_version_info.group(1))
            
        # cves
        exist_cve = False
        cve_pattern = re.compile(r"CVE-[0-9]{4}-[0-9]+")
        for div_text in div_texts:
            cve_info = cve_pattern.search(div_text)
            if cve_info:
                exist_cve = True
                if cve_info.group() not in ghsa_info:
                    ghsa_info.append(cve_info.group())

        if not exist_cve:
            ghsa_info.append(None)

        # optee id
        exist_optee_id = False
        optee_id_pattern = re.compile(r"OP-TEE-[0-9]{4}-[0-9]+")
        for div_text in div_texts:
            optee_id_info = optee_id_pattern.search(div_text)
            if optee_id_info:
                exist_optee_id = True
                if optee_id_info.group() not in ghsa_info:
                    ghsa_info.append(optee_id_info.group())

        if not exist_optee_id:
            ghsa_info.append(None)

        

        # add ghsa_info to cves list 
        print(ghsa_info)
        cves.append(ghsa_info)
    

def get_ghsa():
    i = 1
    exist_content = True
    before_len = 0
    
    while exist_content:
        ghsa_index_page = ghsa_base_url + "?page={}".format(i)
        res = requests.get(ghsa_index_page)
        time.sleep(SLEEP)
        i += 1
        print("[*]Search", ghsa_index_page)
        print("[*]Status Code", res.status_code)
        
        soup = BeautifulSoup(res.text, "html.parser")

        # GHSAを含むtextの抽出
        div_texts = [div.get_text(strip=True) for div in soup.find_all('div')]
        pattern = re.compile(r"GHSA-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}")
        for div_text in div_texts:
            ghsa_pattern = pattern.search(div_text)
            if ghsa_pattern:
                if ghsa_pattern.group() not in ghsa_list:
                    print(ghsa_pattern.group())
                    ghsa_list.append(ghsa_pattern.group())

        if before_len == len(ghsa_list):
            exist_content = False
        before_len = len(ghsa_list)

    print("[*]Total GHSA :", len(ghsa_list))
    

def main():
    # repositoryのghsaの取得
    get_ghsa()

    # ghsaからcve情報の取得
    get_ghsa_info()

    with open('result/'+OUTPUT_FILE, 'w') as f:
        writer = csv.writer(f)
        for cve in cves:
            writer.writerow(cve)

if __name__ == "__main__":
    main()
