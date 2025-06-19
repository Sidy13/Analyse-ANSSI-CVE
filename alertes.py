import pandas as pd
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
 
 
load_dotenv()
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_DESTINATAIRE = os.getenv("EMAIL_DESTINATAIRE")
 
 
def charger_donnees(path="cve_consolidated.csv"):
    return pd.read_csv(path)
 
# Filtrage des CVE critiques
def filtrer_cve_critiques(df, editeurs_cibles=None):
    filtres = (df["Score CVSS"] >= 9.0) & (df["Base Severity"].str.lower() == "critical")
    if editeurs_cibles:
        filtres &= df["Éditeur/Vendor"].isin(editeurs_cibles)
    return df[filtres]
 
 
def generer_message(cve):
    return f""" Alerte de sécurité critique
 
Produit : {cve['Produit']}
Éditeur : {cve['Éditeur/Vendor']}
CVE : {cve['Identifiant CVE']}
Score CVSS : {cve['Score CVSS']}
Score EPSS : {cve['Score EPSS']}
CWE : {cve['Type CWE']}
Description : {cve['Description']}
Lien : {cve['Lien du bulletin']}
"""
 
def envoyer_email(destinataire, sujet, message, sender, password):
    msg = MIMEText(message)
    msg["From"] = sender
    msg["To"] = destinataire
    msg["Subject"] = sujet
 
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, destinataire, msg.as_string())
 
#  Fonction principale exécutée si le fichier est lancé directement
def main():
    df = charger_donnees()
    alertes = filtrer_cve_critiques(df, editeurs_cibles=["Microsoft", "Apache", "Cisco"])
    print(f"{len(alertes)} alertes critiques détectées")
 
    for _, cve in alertes.head(3).iterrows():  
        message = generer_message(cve)
        print(message)  
        envoyer_email(
            destinataire=EMAIL_DESTINATAIRE,
            sujet=f"[ALERTE CVE] {cve['Identifiant CVE']}",
            message=message,
            sender=EMAIL_SENDER,
            password=EMAIL_PASSWORD
        )
 
    #  Sauvegarde dess alertes critiques détectées dans un CSV
    alertes.to_csv("alertes_critiques.csv", index=False, encoding="utf-8")
    print(" Fichier 'alertes_critiques.csv' exporté.")
 
 
if __name__ == "__main__":
    main()
 
 