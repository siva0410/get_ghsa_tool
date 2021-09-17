import argparse
import csv

from get_ghsa import *
from get_cve_info import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o','--output', default='output.csv', help='output file name')
    args = parser.parse_args()
    
    # get GHSA IDs from repository
    get_ghsa()

    # get CVE ID from GHSA ID
    get_ghsa_info()
    
    with open('result/'+args.output, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["GHSA ID", "Affected version", "CVE ID", "CVSSv2", "CVSSv3", "CWE ID", "Description"])
        for cve in cves:
            print(cve[2])
            # if CVE ID exists, get CWE and CVSS from NVD
            if cve[2]:                
                cve += get_cve_info(cve[2])            
            writer.writerow(cve)


if __name__ == "__main__":
    main()
