import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns #joli thème pour les graphes

# Optionnel : joli thème pour les graphes
sns.set(style="whitegrid")


# Charger les données consolidées depuis le fichier CSV
df = pd.read_csv("cve_consolidated.csv")

# Afficher les 5 premières lignes
print("\n--- Aperçu des données ---")
print(df.head())

# Afficher des informations générales sur les colonnes et types de données
print("\n--- Informations générales ---")
print(df.info())

# Afficher le nombre total de lignes
print(f"\nNombre total de lignes : {len(df)}")


# ANALYSES DESCRIPTIVES


# Top 10 des éditeurs les plus touchés
print("\n--- Top 10 des éditeurs les plus touchés ---")
print(df["Éditeur/Vendor"].value_counts().head(10))

# Top 10 des produits les plus cités
print("\n--- Top 10 des produits les plus touchés ---")
print(df["Produit"].value_counts().head(10))

# Top 10 des types de vulnérabilités les plus fréquents (CWE)
print("\n--- Top 10 des types de vulnérabilité (CWE) ---")
print(df["Type CWE"].value_counts().head(10))

# Répartition des niveaux de sévérité (Base Severity)
print("\n--- Répartition des niveaux de sévérité (Base Severity) ---")
print(df["Base Severity"].value_counts())



# Graphe 1 : Top 10 éditeurs
top_vendors = df["Éditeur/Vendor"].value_counts().head(10)

plt.figure(figsize=(10, 6))
sns.barplot(x=top_vendors.values, y=top_vendors.index, palette="Blues_d")
plt.title("Top 10 des éditeurs les plus concernés par des CVE")
plt.xlabel("Nombre de CVE")
plt.ylabel("Éditeur")
plt.tight_layout()
plt.savefig("graphe_top_editeurs.png")  
plt.show()


# Graphe 2 : Top 10 types de failles (CWE)
top_cwe = df["Type CWE"].value_counts().head(10)

plt.figure(figsize=(10, 6))
sns.barplot(x=top_cwe.values, y=top_cwe.index, palette="Oranges_d")
plt.title("Top 10 des types de vulnérabilités (CWE)")
plt.xlabel("Nombre de CVE")
plt.ylabel("Type CWE")
plt.tight_layout()
plt.savefig("graphe_types_cwe.png")
plt.show()

#Graphe 3 : Niveaux de sévérité CVSS
severity_counts = df["Base Severity"].value_counts()

plt.figure(figsize=(8, 6))
sns.barplot(x=severity_counts.index, y=severity_counts.values, palette="Reds")
plt.title("Répartition des niveaux de sévérité (CVSS)")
plt.xlabel("Niveau de sévérité")
plt.ylabel("Nombre de CVE")
plt.tight_layout()
plt.savefig("graphe_severite.png")
plt.show()

# Graphe 4 : Camembert des niveaux de sévérité
severity_counts = df["Base Severity"].value_counts()

plt.figure(figsize=(7, 7))  # Taille du graphique
plt.pie(
    severity_counts.values,  # Nombre de CVE par niveau
    labels=severity_counts.index,  # Niveaux (CRITICAL, HIGH, etc.)
    autopct='%1.1f%%',  # Affiche les pourcentages
    startangle=140,  # Rotation initiale pour une meilleure présentation
    colors=sns.color_palette("Reds", len(severity_counts))  # Palette rouge
)
plt.title("Répartition des niveaux de sévérité (CVSS)")
plt.axis("equal")  # Garde un cercle parfait
plt.tight_layout()  # Ajuste l'espacement
plt.savefig("camembert_severite.png")  # Sauvegarde en image
plt.show()  # Affiche à l'écran

# Graphe 5 : Camembert des types de vulnérabilités (CWE)
top_cwe = df["Type CWE"].value_counts().head(10)  # On prend les 10 CWE les plus fréquents

plt.figure(figsize=(7, 7))
plt.pie(
    top_cwe.values,  # Nombre d’occurrences pour chaque CWE
    labels=top_cwe.index,  # Les identifiants CWE (ex: CWE-79)
    autopct='%1.1f%%',  # Affichage des pourcentages
    startangle=140,  # Orientation initiale
    colors=sns.color_palette("pastel", len(top_cwe))  # Couleurs douces
)
plt.title("Top 10 des types de vulnérabilités (CWE)")
plt.axis("equal")
plt.tight_layout()
plt.savefig("camembert_types_cwe.png")
plt.show()



# Graphe 6 : Nombre de CVE publiés par année
# Convertit la date en datetime (format date utilisable)
df["Date de publication"] = pd.to_datetime(df["Date de publication"], errors='coerce')

# Crée une nouvelle colonne "Année"
df["Année"] = df["Date de publication"].dt.year

# Compte le nombre de CVE par année
cve_par_annee = df["Année"].value_counts().sort_index()

# Affiche le graphique
plt.figure(figsize=(10, 6))
sns.lineplot(x=cve_par_annee.index, y=cve_par_annee.values, marker="o", color="teal")
plt.title("Nombre de CVE publiés par année")
plt.xlabel("Année")
plt.ylabel("Nombre de CVE")
plt.grid(True)
plt.tight_layout()
plt.savefig("graphe_cve_par_annee.png")
plt.show()


# Graphe 7 : Corrélation entre score CVSS et score EPSS
# On enlève les lignes où CVSS ou EPSS est manquant
df_corr = df.dropna(subset=["Score CVSS", "Score EPSS"])

plt.figure(figsize=(10, 6))
sns.scatterplot(
    data=df_corr,
    x="Score CVSS",
    y="Score EPSS",
    hue="Base Severity",  # Colorié selon la gravité
    palette="Set1",
    alpha=0.7
)
plt.title("Corrélation entre le score CVSS et le score EPSS")
plt.xlabel("Score CVSS (gravité)")
plt.ylabel("Score EPSS (exploitabilité)")
plt.grid(True)
plt.tight_layout()
plt.savefig("graphe_cvss_vs_epss.png")
plt.show()


"""# Analyse : CVE critiques ET très exploitables
cve_critiques = df[
    (df["Score CVSS"] >= 9.0) &
    (df["Score EPSS"] >= 0.7)
].sort_values(by=["Score CVSS", "Score EPSS"], ascending=False)

print("\n--- CVE critiques et très exploitables (CVSS ≥ 9 et EPSS ≥ 0.7) ---")
print(cve_critiques[[
    "Identifiant CVE", "Éditeur/Vendor", "Produit", "Score CVSS", "Score EPSS", "Type CWE"
]].head(10))

# Analyse : CVE à forte gravité mais peu exploitables
cve_sous_estimees = df[
    (df["Score CVSS"] >= 8.0) &
    (df["Score EPSS"] < 0.1)
].sort_values(by="Score CVSS", ascending=False)

print("\n--- CVE graves mais peu exploitables (CVSS ≥ 8 et EPSS < 0.1) ---")
print(cve_sous_estimees[[
    "Identifiant CVE", "Éditeur/Vendor", "Produit", "Score CVSS", "Score EPSS", "Type CWE"
]].head(10))"""