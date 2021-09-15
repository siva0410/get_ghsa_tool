import json
import requests
import re
import time

from bs4 import BeautifulSoup

access_token = "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"
endpoint = "https://api.github.com/graphql"
repo_url = "https://github.com/OP-TEE/optee_os"
ghsa_base_url = repo_url + "/security/advisories"
ghsa_list = []
cves = []


def get_ghsa_info():

    for ghsa in ghsa_list:
        ghsa_info = [ghsa]
        ghsa_url = ghsa_base_url + "/" + ghsa
        res = requests.get(ghsa_url)
        time.sleep(0.5)
        print("[*]Search", ghsa_url)
        print("[*]Status Code", res.status_code)
        
        soup = BeautifulSoup(res.text, "html.parser")

        div_texts = [div.get_text(strip=True) for div in soup.find_all('div')]
        
        # Affected version
        affected_version_pattern = re.compile(r"<=? ([0-9]+.[0-9]+.[0-9]+|All versions)")
        for div_text in div_texts:
            affected_version_info = affected_version_pattern.search(div_text)
            if affected_version_info:
                if affected_version_info.group(1) not in ghsa_info:
                    ghsa_info.append(affected_version_info.group(1))
                    print(ghsa_info)

        # cves
        exist_cve = False
        cve_pattern = re.compile(r"CVE-[0-9]{4}-[0-9]{5}")
        for div_text in div_texts:
            cve_info = cve_pattern.search(div_text)
            if cve_info:
                exist_cve = True
                if cve_info.group() not in ghsa_info:
                    ghsa_info.append(cve_info.group())
                    print(ghsa_info)

        if not exist_cve:
            ghsa_info.append(None)

def get_ghsa():
    i = 1
    exist_content = True
    before_len = 0
    
    while exist_content:
        ghsa_index_page = ghsa_base_url + "?page={}".format(i)
        res = requests.get(ghsa_index_page)
        time.sleep(1)
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
    

def post(query):
    headers = {"Authorization": "Bearer {}".format(access_token)}
    res = requests.post(endpoint, json=query, headers=headers)
    if res.status_code != 200:
        raise Execption("failed : {}".format(res.status_code))
    return res.json()


def main():
    query ={ 'query' :  """
query {
  securityAdvisory(ghsaId: "GHSA-w8ww-55c8-83vh"){
    ghsaId
    summary
  }
}
"""
}

    # OP-TEEのghsaの取得
    get_ghsa()
    get_ghsa_info()

    # GitHubAPIから脆弱性情報を取得
    # for ghsa in ghsa_list:
    # print(query)
    # res = post(query)
    # print('{}'.format(json.dumps(res)))


if __name__ == "__main__":
    main()
