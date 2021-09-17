import requests
import re
import time

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
        affected_version_pattern = re.compile(r"<=? ([0-9]+.[0-9]+[.0-9]*)")
        affected_all_version_pattern = re.compile(r"All versions")
        for div_text in div_texts:
            affected_version_info = affected_version_pattern.search(div_text)
            affected_all_version_info = affected_all_version_pattern.search(div_text)            
            if affected_version_info:
                exist_affected_version = True
                if affected_version_info.group(0) not in ghsa_info:
                    ghsa_info.append(affected_version_info.group(0))
            elif affected_all_version_info:
                exist_affected_version = True
                if affected_all_version_info.group(0) not in ghsa_info:
                    ghsa_info.append(affected_all_version_info.group(0))

        if not exist_affected_version:
            ghsa_info.append(None)
            
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
