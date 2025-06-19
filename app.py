import streamlit as st
import pandas as pd
import plotly.express as px
from alertes import filtrer_cve_critiques, generer_message, envoyer_email
from dotenv import load_dotenv
import os
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# Configuration Streamlit
st.set_page_config(page_title="Dashboard CVE", layout="wide")

# Chargement de l'environnement
load_dotenv()
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_DESTINATAIRE = os.getenv("EMAIL_DESTINATAIRE")

# Chargement des données
@st.cache_data
def charger_donnees(path="cve_consolidated.csv"):
    df = pd.read_csv(path)
    df["Date de publication"] = pd.to_datetime(df["Date de publication"], errors="coerce")
    return df

df = charger_donnees()

st.title("📊 Dashboard CVE – Projet Mastercamp 2025")

# Déclaration des onglets
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔍 Analyse & alertes",
    "📊 Statistiques",
    "ℹ️ À propos",
    "📓 Notebook",
    "🤖 Machine Learning"
])

# ───────────────────────────────────────────────
# TAB 1 : Analyse & alertes
# ───────────────────────────────────────────────
with tab1:
    col1, col2, col3 = st.columns(3)
    col1.metric("🔢 Total CVE", len(df))
    col2.metric("⚠️ Critiques (CVSS ≥ 9)", df[df["Score CVSS"] >= 9].shape[0])
    col3.metric("📬 Alertes envoyables", df[df["Score EPSS"] >= 0.7].shape[0])

    st.sidebar.header("🎛️ Filtres dynamiques")
    editeurs = st.sidebar.multiselect("Éditeurs à surveiller", options=sorted(df["Éditeur/Vendor"].dropna().unique()), default=["Microsoft", "Cisco"])
    score_cvss_min = st.sidebar.slider("Score CVSS minimum", 0.0, 10.0, 9.0)
    score_epss_min = st.sidebar.slider("Score EPSS minimum", 0.0, 1.0, 0.7)
    options_severite = sorted(df["Base Severity"].dropna().str.lower().unique())
    severite = st.sidebar.multiselect("Gravité (Base Severity)", options=options_severite, default=["critical"])

    df_filtre = df[
        (df["Score CVSS"] >= score_cvss_min) &
        (df["Score EPSS"] >= score_epss_min) &
        (df["Éditeur/Vendor"].isin(editeurs)) &
        (df["Base Severity"].str.lower().isin(severite))
    ]

    st.success(f"{len(df_filtre)} CVE détectées selon vos critères.")
    st.subheader("📄 Données filtrées")
    st.dataframe(df_filtre[["Identifiant CVE", "Éditeur/Vendor", "Produit", "Score CVSS", "Score EPSS", "Base Severity"]])

    st.subheader("✉️ Envoi d’alertes email")
    if st.button("Envoyer les alertes par mail"):
        nb_envoyes = 0
        for _, cve in df_filtre.drop_duplicates(subset="Identifiant CVE").iterrows():
            message = generer_message(cve)
            try:
                envoyer_email(
                    destinataire=EMAIL_DESTINATAIRE,
                    sujet=f"[ALERTE CVE] {cve['Identifiant CVE']}",
                    message=message,
                    sender=EMAIL_SENDER,
                    password=EMAIL_PASSWORD
                )
                nb_envoyes += 1
            except Exception as e:
                st.error(f"Erreur d'envoi pour {cve['Identifiant CVE']} : {e}")
        st.success(f"{nb_envoyes} alertes envoyées avec succès ✅")

    st.download_button(
        label="📥 Télécharger les CVE filtrées",
        data=df_filtre.to_csv(index=False).encode("utf-8"),
        file_name="alertes_filtrees.csv",
        mime="text/csv"
    )

    st.subheader("🎯 Focus sur la CVE la plus critique")
    if not df_filtre.empty:
        cve_max = df_filtre.sort_values(by="Score EPSS", ascending=False).iloc[0]
        with st.expander(f"Détails de {cve_max['Identifiant CVE']}"):
            st.markdown(f"""
            - **Produit** : {cve_max['Produit']}
            - **Éditeur** : {cve_max['Éditeur/Vendor']}
            - **Score CVSS** : {cve_max['Score CVSS']}
            - **Score EPSS** : {cve_max['Score EPSS']}
            - **Type de vulnérabilité (CWE)** : {cve_max['Type CWE']}
            - **Gravité** : {cve_max['Base Severity']}
            - **Date de publication** : {cve_max['Date de publication'].date()}
            - **Lien** : [Lien vers le bulletin]({cve_max['Lien du bulletin']})
            - **Description** : {cve_max['Description'][:400]}...
            """)

# ───────────────────────────────────────────────
# TAB 2 : Statistiques
# ───────────────────────────────────────────────
with tab2:
    st.subheader("📊 Statistiques globales")

    col6, col7, col8 = st.columns(3)
    col6.metric("🧩 Produits impactés", df["Produit"].nunique())
    col7.metric("🏢 Éditeurs différents", df["Éditeur/Vendor"].nunique())
    col8.metric("📅 Période couverte", f"{df['Date de publication'].min().date()} → {df['Date de publication'].max().date()}")

    st.markdown("### 📌 Répartition et tendances")

    col9, col10 = st.columns(2)
    with col9:
        st.markdown("#### 🔝 Top 10 éditeurs les plus touchés")
        top_vendors = df["Éditeur/Vendor"].value_counts().head(10)
        fig_vendors = px.bar(x=top_vendors.index, y=top_vendors.values, labels={"x": "Éditeur", "y": "Nombre de CVE"}, title="Éditeurs les plus impactés")
        st.plotly_chart(fig_vendors, use_container_width=True)

    with col10:
        st.markdown("#### 🚨 Répartition par gravité")
        severites = df["Base Severity"].value_counts()
        fig_sev = px.pie(names=severites.index, values=severites.values, title="Répartition des niveaux de gravité", hole=0.3)
        st.plotly_chart(fig_sev, use_container_width=True)

    st.markdown("### 📈 CVE par mois")
    df["Mois_dt"] = df["Date de publication"].dt.to_period("M").dt.to_timestamp()
    fig_mensuel = px.line(
        df.groupby("Mois_dt").size().reset_index(name="Nombre de CVE"),
        x="Mois_dt", y="Nombre de CVE",
        title="Évolution mensuelle des CVE publiées"
    )
    st.plotly_chart(fig_mensuel, use_container_width=True)

    st.markdown("### 🧪 Top 10 produits les plus vulnérables")
    top_produits = df["Produit"].value_counts().head(10)
    fig_produits = px.bar(x=top_produits.index, y=top_produits.values, labels={"x": "Produit", "y": "Nombre de CVE"}, title="Produits avec le plus de CVE")
    st.plotly_chart(fig_produits, use_container_width=True)

# ───────────────────────────────────────────────
# TAB 3 : À propos
# ───────────────────────────────────────────────
with tab3:
    st.markdown("""
    ## 🔐 Contexte

    Ce projet vise à automatiser la **surveillance des vulnérabilités de cybersécurité** à partir des publications officielles de l'ANSSI.

    Les données sont enrichies via :
    - L'API **MITRE** pour les détails techniques (CWE, CVSS)
    - L'API **EPSS** pour la probabilité d'exploitation
    - Les bulletins **avis** et **alertes** du [CERT-FR](https://www.cert.ssi.gouv.fr/)

    ## 🎯 Objectifs
    - Identifier rapidement les menaces critiques
    - Permettre une réaction proactive (envoi d’alertes)
    - Visualiser l’évolution des risques dans le temps

    ## 📂 Fonctionnalités
    - Filtres dynamiques (éditeur, gravité, score, date…)
    - Envoi automatisé d’email d’alerte
    - Export CSV des vulnérabilités critiques
    - Graphiques de suivi

    ---
    ✅ **Projet Mastercamp 2025** – Réalisé par : Sidy Doucoure, Ilyesse Essalihi, Samy Boudiba, Diaby Diakite 
    🔗 [ANSSI - CERT-FR](https://www.cert.ssi.gouv.fr/) | 🛠️ Python • Pandas • Streamlit • Plotly  
    
    """)

# ───────────────────────────────────────────────
# TAB 4 : Notebook HTML (analyse_cve.html)
# ───────────────────────────────────────────────
with tab4:
    st.subheader("📓 Analyse exploratoire – Notebook Jupyter")
    try:
        with open("analyse_cve.html", "r", encoding="utf-8") as f:
            notebook_html = f.read()
        st.components.v1.html(notebook_html, height=1000, scrolling=True)
    except FileNotFoundError:
        st.error("❌ Le fichier `analyse_cve.html` est introuvable. Assurez-vous qu'il est bien dans le même dossier que `app.py`.")
 
with tab5:
    st.header("Machine Learning : Clustering & Classification")

    # Préparation des données
    df_ml = df[['Score CVSS', 'Score EPSS', 'Type CWE', 'Éditeur/Vendor', 'Base Severity']].copy()
    df_ml.dropna(inplace=True)

    # Encodage des colonnes catégorielles avec mise en cache
    @st.cache_data
    def encode_data(df_in):
        le_cwe = LabelEncoder()
        le_vendor = LabelEncoder()
        le_severity = LabelEncoder()

        df_in['Type CWE Encoded'] = le_cwe.fit_transform(df_in['Type CWE'].astype(str))
        df_in['Éditeur/Vendor Encoded'] = le_vendor.fit_transform(df_in['Éditeur/Vendor'].astype(str))
        df_in['Base Severity Encoded'] = le_severity.fit_transform(df_in['Base Severity'].astype(str))
        return df_in, le_cwe, le_vendor, le_severity

    df_ml, le_cwe, le_vendor, le_severity = encode_data(df_ml)

    # Features et target
    X = df_ml[['Score CVSS', 'Score EPSS', 'Type CWE Encoded']]
    y = df_ml['Base Severity Encoded']

    # Normalisation
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Choix interactif du nombre de clusters
    n_clusters = st.slider("Nombre de clusters KMeans", min_value=2, max_value=10, value=3, step=1)

    # Clustering KMeans
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    clusters = kmeans.fit_predict(X_scaled)
    df_ml['Cluster'] = clusters

    st.subheader("Clustering KMeans")
    st.write(f"Nombre de clusters : {n_clusters}")
    st.dataframe(df_ml[['Score CVSS', 'Score EPSS', 'Type CWE', 'Cluster']].head(10))

    # Visualisation clustering CVSS vs EPSS (figsize réduit)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.scatterplot(
        data=df_ml,
        x="Score CVSS",
        y="Score EPSS",
        hue="Cluster",
        palette="Set2",
        ax=ax
    )
    ax.set_title("Clustering des vulnérabilités (CVSS vs EPSS)")
    st.pyplot(fig)

    # Classification Random Forest
    st.subheader("Classification Random Forest sur la sévérité")
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.5, random_state=42)
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    st.text("Rapport de classification :")
    labels_presentes = sorted(list(set(y_test)))
    report = classification_report(
        y_test,
        y_pred,
        labels=labels_presentes,
        target_names=le_severity.inverse_transform(labels_presentes)
    )
    st.text(report)

    # Matrice de confusion (figsize réduit)
    conf_mat = confusion_matrix(y_test, y_pred)
    fig2, ax2 = plt.subplots(figsize=(5, 4))
    sns.heatmap(conf_mat, annot=True, fmt='d', cmap='Blues',
                xticklabels=le_severity.classes_, yticklabels=le_severity.classes_, ax=ax2)
    ax2.set_xlabel("Valeurs prédites")
    ax2.set_ylabel("Valeurs réelles")
    ax2.set_title("Matrice de confusion")
    st.pyplot(fig2)

    # Importance des variables (figsize réduit)
    importances = clf.feature_importances_
    features = ['Score CVSS', 'Score EPSS', 'Type CWE']
    fig3, ax3 = plt.subplots(figsize=(5, 3))
    sns.barplot(x=importances, y=features, ax=ax3)
    ax3.set_title("Importance des variables (Random Forest)")
    st.pyplot(fig3)

    # Prédiction interactive
    st.subheader("Prédiction interactive de la sévérité")

    # Construire une liste avec index et Identifiant CVE
    options = [f"{idx} - {cve}" for idx, cve in zip(df_ml.index, df.loc[df_ml.index, 'Identifiant CVE'])]

    choix = st.selectbox("Choisir un CVE par index", options)

    if choix:
        idx_selectionne = int(choix.split(" - ")[0])
        sample = X_scaled[idx_selectionne].reshape(1, -1)
        pred_code = clf.predict(sample)[0]
        pred_severity = le_severity.inverse_transform([pred_code])[0]
        st.write(f"Prédiction de la sévérité : **{pred_severity}**")