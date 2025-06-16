import pandas as pd
import smtplib
from email.mime.text import MIMEText

# Chargement du fichier consolidé
def charger_donnees(path="cve_consolidated.csv"):
    return pd.read_csv(path)

# Filtrage des alertes critiques (score CVSS ≥ 9 et severité CRITICAL)
def filtrer_cve_critiques(df, editeurs_cibles=None):
    filtres = (df["Score CVSS"] >= 9.0) & (df["Base Severity"].str.lower() == "critical")
    if editeurs_cibles:
        filtres &= df["Éditeur/Vendor"].isin(editeurs_cibles)
    return df[filtres]

# Génération d’un message texte lisible pour un humain
def generer_message(cve):
    return f"""🚨 Alerte de sécurité critique 🚨

Produit : {cve['Produit']}
Éditeur : {cve['Éditeur/Vendor']}
CVE : {cve['Identifiant CVE']}
Score CVSS : {cve['Score CVSS']}
Score EPSS : {cve['Score EPSS']}
CWE : {cve['Type CWE']}
Description : {cve['Description']}
Lien : {cve['Lien du bulletin']}
"""

# Fonction d’envoi d’email (optionnelle si tu veux activer la notification)
def envoyer_email(destinataire, sujet, message, sender, password):
    msg = MIMEText(message)
    msg["From"] = sender
    msg["To"] = destinataire
    msg["Subject"] = sujet

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, destinataire, msg.as_string())

# Fonction principale
def main():
    df = charger_donnees()
    alertes = filtrer_cve_critiques(df, editeurs_cibles=["Microsoft", "Apache", "Cisco"])
    print(f"{len(alertes)} alertes critiques détectées")

    for _, cve in alertes.iterrows():
        message = generer_message(cve)
        print(message)  # Affichage console pour debug

        # --- Décommenter si tu veux envoyer un mail ---
        # envoyer_email(
        #     destinataire="ton_email@example.com",
        #     sujet=f"[ALERTE CVE] {cve['Identifiant CVE']}",
        #     message=message,
        #     sender="ton_email@gmail.com",
        #     password="mot_de_passe_app"
        # )

    # Export de toutes les alertes détectées dans un fichier CSV
    alertes.to_csv("alertes_critiques.csv", index=False, encoding="utf-8")
    print("✅ Fichier 'alertes_critiques.csv' exporté.")

if __name__ == "__main__":
    main()
