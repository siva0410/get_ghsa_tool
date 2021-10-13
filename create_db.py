import sqlite3

def create_db(conn, cur):
    # create tables
    ## ghsa table
    ## |---------+------------------+--------|
    ## | ghsa_id | affected_version | cve_id |
    ## |---------+------------------+--------|
    ## | TEXT    | TEXT             | TEXT   |
    ## |---------+------------------+--------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS ghsa(ghsa_id TEXT PRIMARY KEY, affected_version TEXT, cve_id TEXT)
""")

    ## cve table
    ## |--------+---------+---------|
    ## | cve_id | cvss_v2 | cvss_v3 |
    ## |--------+---------+---------|
    ## | TEXT   | REAL    | REAL    |
    ## |--------+---------+---------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS cve(cve_id TEXT PRIMARY KEY, cvss_v2 REAL, cvss_v3 REAL)
""")

    ## cve_cwe table
    ## |--------+--------|
    ## | cve_id | cwe_id |
    ## |--------+--------|
    ## | TEXT   | TEXT   |
    ## |--------+--------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS cve_cwe(cve_id TEXT, cwe_id TEXT, PRIMARY KEY(cve_id, cwe_id))
""")

    ## cwe table
    ## |--------+-------------|
    ## | cwe_id | description |
    ## |--------+-------------|
    ## | TEXT   | TEXT        |
    ## |--------+-------------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS cwe(cwe_id TEXT PRIMARY KEY, description TEXT)
""")

    conn.commit()


def insert_db(conn, cur):
    # insert value to table 'GHSA-3hg3-f4rp-pr44', '< 3.12.0', 'CVE-2020-13799'
    try:
        cur.execute("""
INSERT INTO ghsa(ghsa_id, affected_version, cve_id) values('GHSA-3hg3-f4rp-pr44', '< 3.12.0', 'CVE-2020-13799')
""")
        conn.commit()
    except:
        cur.execute("""
UPDATE ghsa SET ghsa_id = 'GHSA-3hg3-f4rp-pr44',
affected_version = '< 3.12.0'
cve_id = 'CVE-2020-13799'
""")
        conn.commit()
    try:
        cur.execute("""
INSERT INTO cve(cve_id, cvss_v2, cvss_v3) values('CWE-787', 1.9, 4.9)
""")
        conn.commit()
    except:
        cur.execute("""
UPDATE cve SET cve_id = 'CWE-787', cvss_v2 = 1.9, cvss_v3= 4.9)
""")
    try:
        cur.execute("""
INSERT INTO cve(cve_id, cvss_v2, cvss_v3) values('CWE-190', 1.9, 4.9)
""")
        conn.commit()
    except:
        cur.execute("""
UPDATE cve SET cve_id = 'CWE-190', cvss_v2 = 1.9, cvss_v3= 4.9)
""")
        
    conn.commit()

def main():
    dbname = "database/test.db"
    
    conn = sqlite3.connect(dbname)
    cur = conn.cursor()
    
    create_db(conn, cur)
    insert_db(conn, cur)
    
    # print tables
    cur.execute("""
SELECT * FROM ghsa, cve
""")
    conn.commit()

    print(cur.fetchall())
    
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
