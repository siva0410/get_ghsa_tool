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
    ## |--------+--------+-----------------|
    ## | cve_id | cwe_id | cve_description |
    ## |--------+--------+-----------------|
    ## | TEXT   | TEXT   | TEXT            |
    ## |--------+--------+-----------------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS cve_cwe(cve_id TEXT, cwe_id TEXT, cve_description TEXT, PRIMARY KEY(cve_id, cwe_id))
""")

    ## cwe table
    ## |--------+-----------------|
    ## | cwe_id | cwe_description |
    ## |--------+-----------------|
    ## | TEXT   | TEXT            |
    ## |--------+-----------------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS cwe(cwe_id TEXT PRIMARY KEY, cwe_description TEXT)
""")

    conn.commit()


def insert_ghsa_table(conn, cur):
    # insert values to ghsa table 'GHSA-3hg3-f4rp-pr44', '< 3.12.0', 'CVE-2020-13799'
    cur.execute("""
UPDATE ghsa
SET ghsa_id = 'GHSA-3hg3-f4rp-pr44',
affected_version = '< 3.12.0',
cve_id = 'CVE-2020-13799'
WHERE ghsa_id = 'GHSA-3hg3-f4rp-pr44';
""")
    cur.execute("""
INSERT OR IGNORE INTO ghsa(ghsa_id, affected_version, cve_id) VALUES('GHSA-3hg3-f4rp-pr44', '< 3.12.0', 'CVE-2020-13799')
""")
    conn.commit()


def insert_cve_table(conn, cur):
    # insert values to cve table
    cur.execute("""
UPDATE cve
SET cve_id = 'CVE-2020-13799',
cvss_v2 = 1.9,
cvss_v3 = 4.9
WHERE cve_id = 'CVE-2020-13799';
""")
    cur.execute("""
INSERT OR IGNORE INTO cve(cve_id, cvss_v2, cvss_v3) VALUES('CVE-2020-13799', 1.9, 4.9)
""")
    conn.commit()


def insert_cve_cwe_table(conn, cur):
    # insert values to cve-cwe table
    cur.execute("""
UPDATE cve_cwe
SET cve_id = 'CVE-2020-13799',
cwe_id = 'CWE-787',
cve_description = 'cve_description'
WHERE cve_id = 'CVE-2020-13799' AND cwe_id = 'CWE-787';
""")
    cur.execute("""
INSERT OR IGNORE INTO cve_cwe(cve_id, cwe_id, cve_description) VALUES('CVE-2020-13799', 'CWE-787', 'cve_description text')
""")
    conn.commit()


def insert_cwe_table(conn, cur):
    # insert values to cwe table
    cur.execute("""
UPDATE cwe
SET cwe_id = 'CWE-787',
cwe_description = 'description text'
WHERE cwe_id = 'CWE-787';
""")
    cur.execute("""
INSERT OR IGNORE INTO cwe(cwe_id, cwe_description) VALUES('CWE-787', 'cwe_description text')
""")
    conn.commit()


def main():
    dbname = "database/test.db"
    
    conn = sqlite3.connect(dbname)
    cur = conn.cursor()
    
    create_db(conn, cur)
    insert_ghsa_table(conn, cur)
    insert_cve_table(conn, cur)
    insert_cve_cwe_table(conn, cur)
    insert_cwe_table(conn, cur)
    
    # print tables
    cur.execute("""
SELECT * FROM ghsa, cve, cve_cwe, cwe
""")
    # conn.commit()

    print(cur.fetchall())
    
    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
