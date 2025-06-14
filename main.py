import feedparser
url = "https://www.cert.ssi.gouv.fr/avis/feed"
rss_feed = feedparser.parse(url)
entrée = 0
for entry in rss_feed.entries:
    print("Entrée numéro :", entrée)
    print("\nTitre :", entry.title)
    print("\nDescription:", entry.description)
    print("\nLien :", entry.link)
    print("\nDate :", entry.published) 
    entrée+=1
    print("\n\n")       