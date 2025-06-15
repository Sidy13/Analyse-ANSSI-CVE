import feedparser
import requests
import re
import time #On l'utilise pour ne pas surcharger les serveurs de l'ANSII comme lors du TD6 où il ne fallait pas surcharger infoclimat
import pandas as pd

def extract_flux_rss(): #Étape 1
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

def extract_cve_from_bulletins(bulletins): #Étape 2
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

def enrich_cves(cve_data):  # Étape 3 : enrichir chaque CVE avec + d'infos
    enriched_data = []  # Liste finale contenant les CVE enrichies

    total = len(cve_data)
    for i, item in enumerate(cve_data, 1):
        print(f"[{i}/{total}] Traitement de la CVE : {item['cve']}")
        cve_id = item["cve"]
        id_anssi = item["id_anssi"]

        # Variables par défaut (si une info est manquante ou en cas d'erreur)
        description = "Non disponible"
        cvss_score = None
        severity = "Non disponible"
        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        produits = []

        try:
            # Appel à l’API MITRE (base officielle des CVE)
            url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            resp_mitre = requests.get(url_mitre)
            mitre_data = resp_mitre.json()

            # Vérifier que la structure attendue est bien là
            if "containers" in mitre_data and "cna" in mitre_data["containers"]:
                cna = mitre_data["containers"]["cna"]

                # Description de la vulnérabilité
                if "descriptions" in cna and cna["descriptions"]:
                    description = cna["descriptions"][0].get("value", "Non disponible")

                # Score CVSS et sévérité
                if "metrics" in cna and cna["metrics"]:
                    metric = cna["metrics"][0]  # on prend la première version
                    for version in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                        if version in metric:
                            cvss_score = metric[version].get("baseScore")
                            severity = metric[version].get("baseSeverity", "Non disponible")
                            break

                # Type de vulnérabilité (CWE)
                if "problemTypes" in cna and cna["problemTypes"]:
                    descs = cna["problemTypes"][0].get("descriptions", [])
                    if descs:
                        cwe = descs[0].get("cweId", "Non disponible")
                        cwe_desc = descs[0].get("description", "Non disponible")

                # Produits affectés
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
            print(f"❌ Erreur lors de l'appel à l'API MITRE pour {cve_id} : {e}")
            # Toutes les valeurs restent par défaut

        try:
            # Appel à l’API EPSS (probabilité que la CVE soit exploitée)
            url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            resp_epss = requests.get(url_epss)
            epss_json = resp_epss.json()
            epss_data = epss_json.get("data", [])
            epss_score = epss_data[0]["epss"] if epss_data else None
        except Exception as e:
            print(f"❌ Erreur lors de l'appel à l'API EPSS pour {cve_id} : {e}")
            epss_score = None

        # Ajout des infos enrichies dans la liste finale
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

    return enriched_data

def consolidation(bulletins, enriched): #Étape 4
    # Indexer les bulletins par leur ID pour accès rapide
    bulletin_dict = {b["id"]: b for b in bulletins}

    lignes = []

    for cve_entry in enriched:
        id_bulletin = cve_entry["id_anssi"]
        cve_id = cve_entry["cve"]

        bulletin = bulletin_dict.get(id_bulletin)
        if not bulletin:
            continue  # sécurité

        # Plusieurs produits possibles par CVE : une ligne par produit
        if cve_entry["produits"]:
            for produit in cve_entry["produits"]:
                lignes.append({
                    "ID du bulletin": id_bulletin,
                    "Titre du bulletin": bulletin["titre"],
                    "Type de bulletin": bulletin["type"],
                    "Date de publication": bulletin["date"],
                    "Lien du bulletin": bulletin["url"],
                    "Identifiant CVE": cve_id,
                    "Description": cve_entry["description"],
                    "Score CVSS": cve_entry["cvss"],
                    "Base Severity": cve_entry["baseSeverity"],
                    "Type CWE": cve_entry["cwe"],
                    "Score EPSS": cve_entry["epss"],
                    "Éditeur/Vendor": produit["vendor"],
                    "Produit": produit["produit"],
                    "Versions affectées": ", ".join(produit["versions"]) if produit["versions"] else "Non précisé"
                })
        else:
            lignes.append({
                "ID du bulletin": id_bulletin,
                "Titre du bulletin": bulletin["titre"],
                "Type de bulletin": bulletin["type"],
                "Date de publication": bulletin["date"],
                "Lien du bulletin": bulletin["url"],
                "Identifiant CVE": cve_id,
                "Description": cve_entry["description"],
                "Score CVSS": cve_entry["cvss"],
                "Base Severity": cve_entry["baseSeverity"],
                "Type CWE": cve_entry["cwe"],
                "Score EPSS": cve_entry["epss"],
                "Éditeur/Vendor": "Inconnu",
                "Produit": "Inconnu",
                "Versions affectées": "Non précisé"
            })

    df = pd.DataFrame(lignes)
    return df

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

    df = consolidation(bulletins, enriched)
    print("\nAperçu du DataFrame consolidé :")
    print(df.head())

if __name__ == "__main__":
    main()
