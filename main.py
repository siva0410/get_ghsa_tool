import argparse
import csv

from get_ghsa import *
from get_cve_info import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o','--output', default='output.csv', help='output file name')
    args = parser.parse_args()
    
    # get GHSA IDs from repository
    ghsa_list = get_ghsa()

    # get CVE ID from GHSA ID
    ghsa_info_list = get_ghsa_info(ghsa_list)

    # get CVSS and CWE ID from CVE ID
    cveId_list = [ghsa_info[2] for ghsa_info in ghsa_info_list]
    cve_info_list = get_cve_info(cveId_list)

    # combine ghsa_info and cve_info
    unite_info_list = [ghsa_info + cve_info for (ghsa_info, cve_info) in zip(ghsa_info_list, cve_info_list)]
        
    # output results to csv
    with open('result/'+args.output, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["GHSA ID", "Affected version", "CVE ID", "CVSSv2", "CVSSv3", "CWE ID", "Description"])
        for unite_info in unite_info_list:
            writer.writerow(unite_info)


if __name__ == "__main__":
    main()
