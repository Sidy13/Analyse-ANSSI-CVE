# Analyse des Bulletins de Sécurité ANSSI – Projet Mastercamp 2025

Ce projet a pour but d’automatiser la récupération et l’analyse des bulletins de sécurité publiés par l’ANSSI (avis et alertes). Il permet d’en extraire les vulnérabilités (CVE), de les enrichir avec des données issues d’APIs publiques, et de produire une analyse visuelle.

## Étapes réalisées

1. **Extraction des bulletins** depuis les flux RSS de l’ANSSI
2. **Extraction des identifiants CVE** à partir des bulletins JSON
3. **Enrichissement des CVE** via :
   - l’API MITRE (description, score CVSS, type CWE, produits concernés…)
   - l’API EPSS (score d’exploitabilité)
4. **Consolidation des données** dans un fichier CSV unique (`cve_consolidated.csv`)
5. **Analyse exploratoire** avec génération automatique de plusieurs graphiques

## Scripts à exécuter

```bash
python main.py         # Génère le fichier CSV à partir des flux ANSSI
python analyse_cve.py  # Charge le CSV et génère les graphiques
