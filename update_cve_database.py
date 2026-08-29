import sqlite3
import json
import os
import sys

# Configuration paths
DB_PATH = "C:\\Security\\cves.db"
CVE_DIR = "C:\\Security\\cvelistV5"

def init_database(cursor):
    """Initializes the database schema and unique constraints."""
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        state TEXT,
        vendor_name TEXT,
        product_name TEXT,
        vulnerable_spec TEXT,
        description TEXT,
        cvss_score REAL,
        UNIQUE(cve_id, product_name, vulnerable_spec)
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_product ON vulnerabilities(product_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve ON vulnerabilities(cve_id);")

def main():
    if not os.path.exists(CVE_DIR):
        print(f"[!] Error: CVE directory not found at {CVE_DIR}. Please check your path.")
        sys.exit(1)

    is_new_db = not os.path.exists(DB_PATH)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure schema is ready
    init_database(cursor)
    conn.commit()

    if is_new_db:
        print("[*] Database not found. Performing full build...")
    else:
        print("[*] Existing database found. Running incremental update (skipping duplicates)...")

    batch = []
    batch_size = 5000
    processed_count = 0

    print("[*] Scanning repository files...")
    for root, dirs, files in os.walk(CVE_DIR):
        for file in files:
            if file.endswith(".json"):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        cve_meta = data.get("cveMetadata", {})
                        cve_id = cve_meta.get("cveId")
                        state = cve_meta.get("state", "PUBLISHED")
                        
                        if not cve_id or state != "PUBLISHED":
                            continue
                            
                        cna = data.get("containers", {}).get("cna", {})
                        
                        # Extract description safely
                        descriptions = cna.get("descriptions", [])
                        desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
                        
                        # Extract CVSS score
                        cvss_score = None
                        metrics = cna.get("metrics", [])
                        for m in metrics:
                            cvss_data = m.get("cvssV3_1") or m.get("cvssV3_0") or m.get("cvssV2_0")
                            if cvss_data:
                                cvss_score = cvss_data.get("baseScore")
                                break

                        # Extract affected software components & version bounds
                        affected_list = cna.get("affected", [])
                        if not affected_list:
                            batch.append((cve_id, state, "n/a", "n/a", "n/a", desc_text, cvss_score))
                        else:
                            for item in affected_list:
                                vendor = item.get("vendor", "n/a")
                                product = item.get("product", "n/a")
                                versions = item.get("versions", [])
                                
                                if not versions:
                                    batch.append((cve_id, state, vendor, product, "n/a", desc_text, cvss_score))
                                else:
                                    for v in versions:
                                        ver_str = v.get("version", "")
                                        less_than = v.get("lessThan", "")
                                        less_than_or_equal = v.get("lessThanOrEqual", "")
                                        status = v.get("status", "")
                                        
                                        if status == "affected" or not status:
                                            if less_than:
                                                spec = f">= {ver_str} < {less_than}"
                                            elif less_than_or_equal:
                                                spec = f">= {ver_str} <= {less_than_or_equal}"
                                            else:
                                                spec = f"Ver: {ver_str}"
                                                
                                            batch.append((cve_id, state, vendor, product, spec, desc_text, cvss_score))
                                            
                                            # Bulk insert batch using INSERT OR IGNORE to skip existing rows instantly
                                            if len(batch) >= batch_size:
                                                cursor.executemany(
                                                    """
                                                    INSERT OR IGNORE INTO vulnerabilities 
                                                    (cve_id, state, vendor_name, product_name, vulnerable_spec, description, cvss_score) 
                                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                                    """, 
                                                    batch
                                                )
                                                conn.commit()
                                                processed_count += len(batch)
                                                print(f"[*] Processed {processed_count} records...", end="\r")
                                                batch = []
                except Exception:
                    continue

    # Flush remaining batch records
    if batch:
        cursor.executemany(
            """
            INSERT OR IGNORE INTO vulnerabilities 
            (cve_id, state, vendor_name, product_name, vulnerable_spec, description, cvss_score) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, 
            batch
        )
        conn.commit()
        processed_count += len(batch)

    conn.close()
    print(f"\n[+] Database operation complete! Total records evaluated/processed: {processed_count}")

if __name__ == "__main__":
    main()