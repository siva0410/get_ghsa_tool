import sqlite3

def create_tables(conn, cur):
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
    ## |--------+---------+---------+-----------------|
    ## | cve_id | cvss_v2 | cvss_v3 | cve_description |
    ## |--------+---------+---------+-----------------|
    ## | TEXT   | REAL    | REAL    | TEXT            |
    ## |--------+---------+---------+-----------------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS cve(cve_id TEXT PRIMARY KEY, cvss_v2 REAL, cvss_v3 REAL, cve_description TEXT)
""")

    ## cve_cwe table
    ## |--------+--------+-----------------|
    ## | cve_id | cwe_id | cve_description |
    ## |--------+--------+-----------------|
    ## | TEXT   | TEXT   | TEXT            |
    ## |--------+--------+-----------------|
    cur.execute("""
CREATE TABLE IF NOT EXISTS cve_cwe(cve_id TEXT, cwe_id TEXT, PRIMARY KEY(cve_id, cwe_id))
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


def insert_ghsa_table(conn, cur, row):
    # insert values to ghsa table 'GHSA-3hg3-f4rp-pr44', '< 3.12.0', 'CVE-2020-13799'
    cur.execute("""
UPDATE ghsa
SET affected_version = :affected_version,
cve_id = :cve_id
WHERE ghsa_id = :ghsa_id;
""", row)
    cur.execute("""
INSERT OR IGNORE INTO ghsa(ghsa_id, affected_version, cve_id) VALUES(:ghsa_id, :affected_version, :cve_id)
""", row)
    conn.commit()


def insert_cve_table(conn, cur, row):
    # insert values to cve table
    cur.execute("""
UPDATE cve
SET cvss_v2 = :cvss_v2,
cvss_v3 = :cvss_v3,
cve_description = :cve_description
WHERE cve_id = :cve_id;
""", row)
    cur.execute("""
INSERT OR IGNORE INTO cve(cve_id, cvss_v2, cvss_v3, cve_description) VALUES(:cve_id, :cvss_v2, :cvss_v3, :cve_description)
""", row)
    conn.commit()


def insert_cve_cwe_table(conn, cur, row):
    # insert values to cve-cwe table
    for cwe in row['cwe_id']:
        cur.execute("""
INSERT OR IGNORE INTO cve_cwe(cve_id, cwe_id) VALUES(:cve_id, :cwe_id)
""", {'cve_id': row['cve_id'], 'cwe_id': cwe})
        conn.commit()


def insert_cwe_table(conn, cur, row):
    # insert values to cwe table
    for cwe in row['cwe_id']:
        cur.execute("""
UPDATE cwe
SET cwe_description = :cwe_description
WHERE cwe_id = :cwe_id;
""", {'cwe_id': cwe, 'cwe_description': 'test'})
        cur.execute("""
INSERT OR IGNORE INTO cwe(cwe_id, cwe_description) VALUES(:cwe_id, :cwe_description)
""", {'cwe_id': cwe, 'cwe_description': 'test'})
        conn.commit()


def insert_db(conn, cur, row):
    insert_ghsa_table(conn, cur, row)
    print(row)
    if row['cve_id']:
        insert_cve_table(conn, cur, row)
        insert_cve_cwe_table(conn, cur, row)
        insert_cwe_table(conn, cur, row)
        
    # print tables
    cur.execute("""
SELECT * FROM ghsa, cve, cve_cwe, cwe
""")
