import argparse
import csv

from get_ghsa import get_ghsa, get_ghsa_info
from get_cve_info import get_cve_info
from operate_db import insert_db

def main():
    # parse argments
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--owner', required=True, help='owner name')
    parser.add_argument('-r', '--repository', required=True, help='repository name')
    parser.add_argument('-o', '--output', default='output.csv', help='output file name')
    args = parser.parse_args()
    OWNER = args.owner
    REPOSITORY = args.repository
    OUTPUT = args.output       

    # get GHSA IDs from repository
    repo_url = "https://github.com/"+OWNER+"/"+REPOSITORY
    ghsa_list = get_ghsa(repo_url)

    # get CVE ID from GHSA ID
    ghsa_info_list = get_ghsa_info(ghsa_list, repo_url)

    # get CVSS and CWE ID from CVE ID
    cveId_list = [ghsa_info[2] for ghsa_info in ghsa_info_list]
    cve_info_list = get_cve_info(cveId_list)

    # combine ghsa_info and cve_info
    unite_info_list = [ghsa_info + cve_info + [] for (ghsa_info, cve_info) in zip(ghsa_info_list, cve_info_list)]
        
    # insert informatin to db
    dbname = "database/"+REPOSITORY+".db"    
    insert_db(dbname, unite_info_list)
    

if __name__ == "__main__":
    main()
