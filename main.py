import feedparser
import requests
import re
import time #On l'utilise pour ne pas surcharger les serveurs de l'ANSII comme lors du TD6 où il ne fallait pas surcharger infoclimat
import pandas as pd

def extract_flux_rss():
    flux_urls = {
        "avis": "https://www.cert.ssi.gouv.fr/avis/feed",
        "alertes": "https://www.cert.ssi.gouv.fr/alerte/feed"
    }

    bulletins = []

    for flux_type, url in flux_urls.items():
        print(f"Chargement du flux {flux_type}")
        rss_feed = feedparser.parse(url)
        for entry in rss_feed.entries:
            bulletin_id = entry.link.split('/')[-2]
            bulletins.append({
                "type": flux_type,
                "id": bulletin_id,
                "titre": entry.title,
                "description": entry.description,
                "url": entry.link,
                "date": entry.published
            })
        time.sleep(0.5)

    return bulletins

def extract_cve_from_bulletins(bulletins):
    cve_data = []

    for bulletin in bulletins:
        try:
            url_json = f"{bulletin['url']}json/"
            response = requests.get(url_json)
            if response.status_code != 200:
                print(f"Échec de récupération JSON pour {bulletin['id']}")
                continue

            data = response.json()

            # CVE depuis la clé "cves"
            cves_direct = data.get("cves", [])
            for cve in cves_direct:
                cve_data.append({"id_anssi": bulletin["id"], "cve": cve["name"]})

            # CVE en fallback via regex
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cves_regex = set(re.findall(cve_pattern, str(data)))
            for cve_id in cves_regex:
                if not any(cve['cve'] == cve_id for cve in cve_data):
                    cve_data.append({"id_anssi": bulletin["id"], "cve": cve_id})

        except Exception as e:
            print(f"Erreur pour le bulletin {bulletin['id']} : {e}")

        #time.sleep(0.5)

    return cve_data

def enrich_cves(cve_data):
    enriched_data = []

    for item in cve_data:
        cve_id = item["cve"]
        id_anssi = item["id_anssi"]

        try:
            url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            resp_mitre = requests.get(url_mitre, timeout=10)
            mitre_data = resp_mitre.json()

            cna = mitre_data["containers"]["cna"]
            description = cna["descriptions"][0]["value"] if cna.get("descriptions") else "Non disponible"

            cvss_score = None
            severity = "Non disponible"
            if "metrics" in cna:
                metric = cna["metrics"][0]
                for version in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                    if version in metric:
                        cvss_score = metric[version].get("baseScore")
                        severity = metric[version].get("baseSeverity", "Non disponible")
                        break

            cwe = "Non disponible"
            cwe_desc = "Non disponible"
            if cna.get("problemTypes"):
                descs = cna["problemTypes"][0].get("descriptions", [])
                if descs:
                    cwe = descs[0].get("cweId", "Non disponible")
                    cwe_desc = descs[0].get("description", "Non disponible")

            produits = []
            for p in cna.get("affected", []):
                vendor = p.get("vendor", "Inconnu")
                product_name = p.get("product", "Inconnu")
                versions_affectees = []
                for v in p.get("versions", []):
                    if v.get("status") == "affected":
                        versions_affectees.append(v.get("version", "N/A"))

                produits.append({
                    "vendor": vendor,
                    "produit": product_name,
                    "versions": versions_affectees
                })


        except Exception as e:
            print(f"Erreur API MITRE pour {cve_id} : {e}")
            description = "Erreur"
            cvss_score = None
            severity = "Non disponible"
            cwe = "Erreur"
            cwe_desc = "Erreur"
            produits = []

        try:
            url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            resp_epss = requests.get(url_epss)
            epss_json = resp_epss.json()
            epss_data = epss_json.get("data", [])
            epss_score = epss_data[0]["epss"] if epss_data else None
        except Exception as e:
            print(f"Erreur API EPSS pour {cve_id} : {e}")
            epss_score = None

        enriched_data.append({
            "id_anssi": id_anssi,
            "cve": cve_id,
            "description": description,
            "cvss": cvss_score,
            "baseSeverity": severity,
            "cwe": cwe,
            "cwe_description": cwe_desc,
            "produits": produits,
            "epss": epss_score
        })

        #time.sleep(2)

    return enriched_data

def main():
    print("=" * 60)
    print("ÉTAPE 1 : Extraction des flux RSS ANSSI (avis + alertes)")
    print("=" * 60)
    bulletins = extract_flux_rss()
    print(f"{len(bulletins)} bulletins récupérés.")

    print("\n" + "=" * 60)
    print("ÉTAPE 2 : Extraction des CVE depuis les bulletins")
    print("=" * 60)
    cve_data = extract_cve_from_bulletins(bulletins)
    print(f"{len(cve_data)} CVE extraits.")

    print("\n" + "=" * 60)
    print("ÉTAPE 3 : Enrichissement des CVE via MITRE et EPSS")
    print("=" * 60)
    enriched = enrich_cves(cve_data)
    print(f"{len(enriched)} CVE enrichis.\n")

    for e in enriched[:3]:
        print("\n--- Exemple ---")
        for k, v in e.items():
            print(f"{k} : {v}")

if __name__ == "__main__":
    main()
