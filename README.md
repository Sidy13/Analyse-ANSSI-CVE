# Analyse des Bulletins de Sécurité ANSSI – Projet Mastercamp 2025

Ce projet a pour but d’automatiser la récupération et l’analyse des bulletins de sécurité publiés par l’ANSSI (avis et alertes). Il permet d’en extraire les vulnérabilités (CVE), de les enrichir avec des données issues d’APIs publiques, et de produire une analyse visuelle.

## Étapes réalisées

1. **Extraction des bulletins** depuis les flux RSS de l’ANSSI
2. **Extraction des identifiants CVE** à partir des bulletins JSON
3. **Enrichissement des CVE** via :
   - l’API MITRE (description, score CVSS, type CWE, produits concernés…)
   - l’API EPSS (score d’exploitabilité)
4. **Consolidation des données** dans un fichier CSV unique (`cve_consolidated.csv`)
5. **Analyse exploratoire** avec génération automatique de plusieurs graphiques (notebook Jupyter)
6. **Détection automatique d’alertes critiques** et **notification e-mail**
7. **Machine Learning, modele supervisé & non supervisé**


## Fichiers à exécuter
Voici l’ordre d’exécution recommandé :

```bash
python main.py
# ➜ Extrait les bulletins, les CVE, les enrichit et génère le fichier final 'cve_consolidated.csv'

jupyter notebook analyse_cve.ipynb
# ➜ Ouvre le notebook pour produire les visualisations (graphiques, camemberts, corrélations)

python alertes.py
# ➜ Identifie les CVE critiques (CVSS ≥ 9, severity CRITICAL) pour certains éditeurs
# ➜ Envoie automatiquement une notification e-mail si configuré
# ➜ Génère un fichier 'alertes_critiques.csv'
```
### Lancez l’application Streamlit (dans votre terminal):

streamlit run app.py

## 🔐 Configuration de l'environnement (.env)

Avant d'exécuter le script, créez un fichier `.env` à la racine du projet pour y stocker vos identifiants de manière sécurisée.
### Exemple de contenu `.env`

```env
EMAIL_SENDER=ton_email@gmail.com
EMAIL_PASSWORD=ton_mot_de_passe_application(à faire avec gmail, voir etapes plus bas)
EMAIL_DESTINATAIRE=destinataire@example.com(tu peux remettre le tien ça fontionne)
```

### Comment créer un mot de passe d'application Gmail
Va sur le site de gestion de ton compte Google :
👉 https://myaccount.google.com

Clique sur "Sécurité" dans le menu à gauche.

Assure-toi que la validation en deux étapes est activée.
Si ce n’est pas le cas, active-la en suivant les instructions.

Une fois activée, une nouvelle option appelée "Mots de passe des applications" apparaîtra plus bas dans la même page.

Clique sur "Mots de passe des applications".
(Lien direct si tu es connecté : https://myaccount.google.com/apppasswords)

Tu devras peut-être retaper ton mot de passe Google.

Dans la page qui s’ouvre :

Choisis "Mail" comme application

Choisis "Autre (nom personnalisé)" pour l’appareil, et entre un nom comme script_cve ou projet_mastercamp

Clique sur "Générer"

Un mot de passe à 16 caractères s'affiche (ex : abcd efgh ijkl mnop).
➜ Copie-le et utilise-le à la place de ton mot de passe Gmail dans ton fichier .env.

### activer env virtuel et installer les bibliotèques:
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt