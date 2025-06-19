import streamlit as st
import pandas as pd
import plotly.express as px
from alertes import filtrer_cve_critiques, generer_message, envoyer_email
from dotenv import load_dotenv
import os

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

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["🔍 Analyse & alertes", "📊 Statistiques", "ℹ️ À propos", "📓 Notebook"])

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
    ✅ **Projet Mastercamp 2025** – Réalisé par : _Ton Nom_  
    🔗 [ANSSI - CERT-FR](https://www.cert.ssi.gouv.fr/) | 🛠️ Python • Pandas • Streamlit • Plotly  
    📬 Contact : [ton.email@exemple.com](mailto:ton.email@exemple.com)
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