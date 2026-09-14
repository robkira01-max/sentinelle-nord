"""Génère le manuel d'utilisation de la plateforme Sentinelle Nord Canada.

Usage :
    python3 reporting/user_manual.py [--out /chemin/manuel.pdf]
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

VERSION = "2.0.0"


def build_manual_html() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<style>
  @page {{
    size: A4;
    margin: 18mm 15mm 18mm 15mm;
    @top-center {{
      content: "SENTINELLE NORD CANADA — MANUEL D'UTILISATION v{VERSION}";
      font-size: 7pt; color: #999; font-family: sans-serif;
    }}
    @bottom-center {{
      content: "Page " counter(page) " / " counter(pages);
      font-size: 7pt; color: #999; font-family: sans-serif;
    }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 9pt;
          color: #1a1a2e; background: white; line-height: 1.5; }}

  .cover {{ text-align: center; padding: 50px 40px 40px;
            background: linear-gradient(160deg, #0a0d14 0%, #0d1a3a 100%);
            color: white; page-break-after: always; }}
  .cover h1 {{ font-size: 24pt; color: #4a9eff; margin-bottom: 6px; }}
  .cover h2 {{ font-size: 13pt; color: #00d4aa; margin-bottom: 25px; }}
  .cover .meta {{ font-size: 8pt; color: #8fa8d0; line-height: 2.2; }}
  hr.div {{ border: none; border-top: 1px solid #2a3a5c; margin: 18px auto; width: 55%; }}

  h2.ch {{ font-size: 13pt; color: #0a1628; border-left: 4px solid #4a9eff;
           padding: 5px 0 5px 10px; margin: 22px 0 10px;
           background: #f0f5ff; page-break-after: avoid; }}
  h3.sec {{ font-size: 10.5pt; color: #1a3a6a; margin: 16px 0 6px;
            border-bottom: 2px solid #dee2f0; padding-bottom: 3px; }}
  h4.sub {{ font-size: 9pt; color: #2a4a7a; margin: 12px 0 4px;
            font-style: italic; }}

  .pb {{ page-break-before: always; }}

  p {{ margin-bottom: 7px; }}
  ul, ol {{ margin: 5px 0 9px 18px; }}
  li {{ margin-bottom: 3px; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 8pt;
           margin-bottom: 10px; }}
  th {{ background: #0a1628; color: white; padding: 4px 8px;
        text-align: left; font-size: 7.5pt; }}
  td {{ padding: 4px 8px; border-bottom: 1px solid #e8ecf5; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #f8faff; }}

  .card {{ border: 1px solid #dee2f0; border-radius: 6px; margin-bottom: 10px; }}
  .card-title {{ background: #f0f5ff; padding: 5px 10px; font-weight: bold;
                 font-size: 8.5pt; color: #1a3a6a;
                 border-bottom: 1px solid #dee2f0; }}
  .card-body {{ padding: 8px 10px; font-size: 8.5pt; }}

  code {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 7.5pt;
          background: #f0f2f8; padding: 1px 4px; border-radius: 2px; }}
  pre {{ background: #0d1117; color: #c9d1d9; padding: 10px 12px;
         border-radius: 5px; font-size: 7.5pt; margin: 6px 0 10px;
         font-family: 'DejaVu Sans Mono', monospace; line-height: 1.5;
         white-space: pre-wrap; word-wrap: break-word; }}
  .note {{ background: #fff8e1; border: 1px solid #ffe082; border-radius: 4px;
           padding: 6px 9px; font-size: 8pt; color: #6d4c41; margin-bottom: 8px; }}
  .warn {{ background: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px;
           padding: 6px 9px; font-size: 8pt; color: #856404; margin-bottom: 8px; }}
  .ok {{ background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px;
         padding: 6px 9px; font-size: 8pt; color: #155724; margin-bottom: 8px; }}
  .badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
            font-size: 7pt; font-weight: bold; }}
  .green  {{ background: #d4edda; color: #155724; }}
  .orange {{ background: #fff3cd; color: #856404; }}
  .red    {{ background: #f8d7da; color: #721c24; }}
  .blue   {{ background: #d1ecf1; color: #0c5460; }}
  .grey   {{ background: #e2e3e5; color: #383d41; }}
  .two-col {{ display: flex; gap: 10px; }}
  .two-col > * {{ flex: 1; }}
  .step {{ display: flex; gap: 10px; margin-bottom: 8px; align-items: flex-start; }}
  .step .num {{ background: #4a9eff; color: white; border-radius: 50%;
                width: 20px; height: 20px; display: flex; align-items: center;
                justify-content: center; font-size: 8pt; font-weight: bold;
                flex-shrink: 0; margin-top: 1px; }}
  .step .body {{ flex: 1; font-size: 8.5pt; }}
  .endpoint {{ background: #0d1117; color: #79c0ff; padding: 3px 8px;
               border-radius: 4px; font-family: monospace; font-size: 8pt;
               margin: 2px 0; display: block; }}
  .method {{ display: inline-block; padding: 1px 5px; border-radius: 3px;
             font-size: 7pt; font-weight: bold; font-family: monospace; }}
  .get  {{ background: #d1ecf1; color: #0c5460; }}
  .post {{ background: #d4edda; color: #155724; }}
</style>
</head>
<body>

<!-- COUVERTURE -->
<div class="cover">
  <div style="font-size:50pt;margin-bottom:10px">🛡️</div>
  <h1>SENTINELLE NORD CANADA</h1>
  <h2>Manuel d'utilisation — Version {VERSION}</h2>
  <hr class="div">
  <div class="meta">
    <div>Plateforme OSINT / Threat Intelligence Arctique</div>
    <div>Généré le : <strong>{now}</strong></div>
    <div>Audience : Analystes sécurité · Administrateurs · Décideurs</div>
    <div>Classification : Usage interne — recon passive uniquement</div>
  </div>
  <hr class="div">
  <div style="font-size:7pt;color:#4a6080;margin-top:15px">
    Flask 3.0 · Python 3.13 · WeasyPrint 70 · Folium · Copernicus EU · ECCC Canada
  </div>
</div>

<!-- ════════════════════════════════════════ -->
<!-- TABLE DES MATIÈRES                       -->
<!-- ════════════════════════════════════════ -->
<h2 class="ch">Table des matières</h2>
<table>
  <tr><td>1.</td><td>Connexion et démarrage rapide</td></tr>
  <tr><td>2.</td><td>Interface web — Tableau de bord</td></tr>
  <tr><td>3.</td><td>Module OSINT — Scan de domaines</td></tr>
  <tr><td>4.</td><td>Pipeline Arctique — Tous les modules</td></tr>
  <tr><td>5.</td><td>Score de risque pondéré</td></tr>
  <tr><td>6.</td><td>Génération de rapports PDF</td></tr>
  <tr><td>7.</td><td>API REST — Référence complète</td></tr>
  <tr><td>8.</td><td>Configuration avancée</td></tr>
  <tr><td>9.</td><td>Sécurité et bonnes pratiques</td></tr>
  <tr><td>10.</td><td>Dépannage</td></tr>
</table>


<!-- ════════════════════════════════════════ -->
<!-- CH. 1 — CONNEXION                        -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">1. Connexion et démarrage rapide</h2>

<h3 class="sec">1.1 Prérequis système</h3>
<table>
  <tr><th>Composant</th><th>Version minimum</th><th>Statut actuel</th></tr>
  <tr><td>Python</td><td>3.11</td><td><span class="badge green">3.13 ✓</span></td></tr>
  <tr><td>Système d'exploitation</td><td>Linux / macOS / Windows WSL2</td><td><span class="badge green">Kali Linux ✓</span></td></tr>
  <tr><td>RAM libre</td><td>512 MB</td><td><span class="badge green">Recommandé 2 GB</span></td></tr>
  <tr><td>Ports requis</td><td>5000 (HTTP local)</td><td><span class="badge orange">Configurable via .env</span></td></tr>
  <tr><td>Internet</td><td>Requis pour recon</td><td><span class="badge blue">NVD, ECCC, Copernicus</span></td></tr>
</table>

<h3 class="sec">1.2 Démarrage de la plateforme</h3>
<div class="step"><div class="num">1</div><div class="body">
  <strong>Activer l'environnement Python</strong><br>
  <pre>cd /home/kali/osint_ti
source .venv/bin/activate</pre>
</div></div>
<div class="step"><div class="num">2</div><div class="body">
  <strong>Lancer le serveur Flask</strong> (scheduler désactivé en dev)
  <pre>SCHEDULER_ENABLED=false python3 app.py</pre>
  Avec scheduler actif (AIS/ADS-B/météo en tâche de fond) :
  <pre>python3 app.py</pre>
</div></div>
<div class="step"><div class="num">3</div><div class="body">
  <strong>Ouvrir le navigateur</strong><br>
  <code>http://127.0.0.1:5000</code>
  <p style="margin-top:4px">Le dashboard Sentinelle Nord Canada s'affiche immédiatement.</p>
</div></div>

<div class="ok">✅ La plateforme est accessible localement uniquement par défaut (127.0.0.1).
Pour l'exposer sur le réseau local : modifier <code>FLASK_HOST=0.0.0.0</code> dans <code>.env</code>.</div>

<h3 class="sec">1.3 Vérification que tout fonctionne</h3>
<pre>curl http://127.0.0.1:5000/api/targets
# Réponse attendue : liste JSON des domaines déjà scannés

curl http://127.0.0.1:5000/north/adsb
# Réponse : vols ADS-B dans la zone 60-90°N Canada</pre>

<div class="warn">⚠️ Ne jamais exposer la plateforme sur Internet sans authentification.
La version actuelle n'a PAS d'authentification intégrée — usage interne uniquement.</div>


<!-- ════════════════════════════════════════ -->
<!-- CH. 2 — INTERFACE WEB                   -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">2. Interface web — Tableau de bord</h2>

<h3 class="sec">2.1 Navigation principale</h3>
<p>Le dashboard est un SPA (Single Page App) — tous les panneaux se chargent sans rechargement de page via des appels AJAX à l'API REST.</p>
<table>
  <tr><th>Panneau</th><th>Icône</th><th>Contenu</th><th>Source de données</th></tr>
  <tr><td><strong>Dashboard</strong></td><td>📊</td><td>Résumé global : nb scans, targets, derniers scans</td><td>SQLite local</td></tr>
  <tr><td><strong>Scan OSINT</strong></td><td>🔍</td><td>Formulaire de scan — saisir un domaine/IP/URL</td><td>DNS, HTTP, WHOIS, NVD, URLScan</td></tr>
  <tr><td><strong>Rapports</strong></td><td>📋</td><td>Historique des scans passés — téléchargement JSON</td><td>SQLite local</td></tr>
  <tr><td><strong>Carte Arctique</strong></td><td>🗺️</td><td>Carte Folium interactive des zones nordiques</td><td>NRCan + Folium offline</td></tr>
  <tr><td><strong>AIS Maritime</strong></td><td>🚢</td><td>Trafic maritime Arctique (zone 60-90°N)</td><td>AISHub (clé requise)</td></tr>
  <tr><td><strong>ADS-B Aviation</strong></td><td>✈️</td><td>Vols actifs en zone polaire canadienne</td><td>OpenSky Network EU</td></tr>
  <tr><td><strong>Satellite</strong></td><td>🛰️</td><td>Produits Sentinel-1/2/3 récents sur l'Arctique</td><td>Copernicus Data Space EU</td></tr>
  <tr><td><strong>Météo</strong></td><td>🌡️</td><td>9 stations ECCC : Resolute Bay, Iqaluit, Churchill…</td><td>MSC DataMart ECCC (CA)</td></tr>
  <tr><td><strong>Infrastructure</strong></td><td>🏭</td><td>19 infras critiques nordiques par catégorie</td><td>NRCan + données publiques</td></tr>
  <tr><td><strong>Glace Marine</strong></td><td>🧊</td><td>4 zones CIS : Arctique Est/Ouest, Baie Hudson, St-Laurent</td><td>CIS/ECCC (souverain CA)</td></tr>
</table>

<h3 class="sec">2.2 Chargement des panneaux</h3>
<p>Chaque panneau est chargé à la demande (<em>lazy loading</em>) au clic. Un spinner s'affiche pendant le chargement. Les données sont récupérées en temps réel depuis les APIs distantes — le premier chargement peut prendre 3–8 secondes.</p>

<h4 class="sub">Comportement en cas d'erreur réseau</h4>
<p>Si une source externe est inaccessible (ex: DataMart ECCC hors ligne), le panneau affiche les métadonnées statiques et un bandeau d'avertissement orange. La plateforme ne plante pas.</p>


<!-- ════════════════════════════════════════ -->
<!-- CH. 3 — MODULE OSINT                    -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">3. Module OSINT — Scan de domaines</h2>

<h3 class="sec">3.1 Lancer un scan</h3>
<div class="step"><div class="num">1</div><div class="body">
Cliquer sur <strong>🔍 Scan OSINT</strong> dans la barre latérale.
</div></div>
<div class="step"><div class="num">2</div><div class="body">
Saisir une cible dans le champ : domaine, IP, ou URL complète.<br>
Exemples : <code>canada.ca</code> · <code>8.8.8.8</code> · <code>https://example.com</code>
</div></div>
<div class="step"><div class="num">3</div><div class="body">
Cliquer sur <strong>Lancer le scan</strong>. Temps typique : 15–45 secondes selon les collectors actifs.
</div></div>
<div class="step"><div class="num">4</div><div class="body">
Les résultats s'affichent dans le panneau. Chaque section est dépliable.
</div></div>

<h3 class="sec">3.2 Collectors disponibles</h3>
<table>
  <tr><th>Collector</th><th>Données collectées</th><th>Activation</th><th>Clé API</th></tr>
  <tr><td><code>dns</code></td><td>A, AAAA, MX, NS, TXT, SOA, CNAME</td><td><span class="badge green">Par défaut</span></td><td>Non</td></tr>
  <tr><td><code>http</code></td><td>Headers sécurité, SSL/TLS, DMARC, SPF, redirections</td><td><span class="badge green">Par défaut</span></td><td>Non</td></tr>
  <tr><td><code>whois</code></td><td>Registrar, dates création/expiration, NS, contacts</td><td><span class="badge green">Par défaut</span></td><td>Non</td></tr>
  <tr><td><code>cve</code></td><td>CVEs NVD API 2.0 filtrés par keyword (cache 6h)</td><td><span class="badge green">Par défaut</span></td><td>Non (rate-limit 5/30s)</td></tr>
  <tr><td><code>urlscan</code></td><td>Captures d'écran, liens, technologies détectées</td><td><span class="badge grey">Optionnel</span></td><td>URLSCAN_API_KEY</td></tr>
  <tr><td><code>shodan</code></td><td>Ports ouverts, bannières, vulnérabilités</td><td><span class="badge grey">Optionnel</span></td><td>SHODAN_API_KEY</td></tr>
  <tr><td><code>censys</code></td><td>Certificats, hôtes, services</td><td><span class="badge grey">Optionnel</span></td><td>CENSYS_API_ID + SECRET</td></tr>
</table>

<h3 class="sec">3.3 Lire les résultats</h3>
<div class="two-col">
  <div class="card">
    <div class="card-title">Section DNS</div>
    <div class="card-body">
      Tous les enregistrements DNS résolus. Les <strong>TXT records</strong> révèlent souvent le stack SaaS (SPF = Microsoft, Google, Adobe…). Les <strong>NS</strong> identifient le registrar DNS.
    </div>
  </div>
  <div class="card">
    <div class="card-title">Section HTTP / Sécurité email</div>
    <div class="card-body">
      DMARC et SPF analysés. Un DMARC <code>p=none</code> = spoofing possible. Un SPF <code>~all</code> (softfail) = l'email non autorisé n'est pas rejeté.
    </div>
  </div>
</div>
<div class="two-col">
  <div class="card">
    <div class="card-title">Section SSL/TLS</div>
    <div class="card-body">
      Émetteur, expiration, SANs (alternate names). Les SANs révèlent souvent d'autres domaines/sous-domaines de la même organisation.
    </div>
  </div>
  <div class="card">
    <div class="card-title">Section CVE</div>
    <div class="card-body">
      CVEs NVD filtrés par le keyword (premier label du domaine par défaut, ou <code>CVE_KEYWORD</code> dans .env). Configurer un keyword précis (ex: "drupal", "wordpress") pour des résultats pertinents.
    </div>
  </div>
</div>

<h3 class="sec">3.4 Comparer deux scans (delta)</h3>
<p>La route <code>GET /api/delta?a=&#123;id1&#125;&amp;b=&#123;id2&#125;</code> compare deux scans du même domaine et retourne les différences (nouvelles vulnérabilités, corrections, changements DNS).</p>
<pre>curl "http://127.0.0.1:5000/api/delta?a=1&b=2"</pre>


<!-- ════════════════════════════════════════ -->
<!-- CH. 4 — PIPELINE ARCTIQUE               -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">4. Pipeline Arctique — Tous les modules</h2>

<h3 class="sec">4.1 AIS Maritime (AISHub)</h3>
<p>Surveillance du trafic maritime en zone 60–90°N Canada (Passage du Nord-Ouest, Mer de Beaufort, Baie de Baffin).</p>
<div class="card">
  <div class="card-title">Configuration requise</div>
  <div class="card-body">
    <ol>
      <li>S'inscrire sur <code>www.aishub.net</code> (gratuit)</li>
      <li>Obtenir la clé API dans le profil</li>
      <li>Ajouter dans <code>.env</code> : <code>AISHUB_API_KEY=votre_cle</code></li>
    </ol>
  </div>
</div>
<table>
  <tr><th>Paramètre</th><th>Défaut</th><th>Description</th></tr>
  <tr><td><code>lat_min</code></td><td>60</td><td>Latitude minimale (degrés N)</td></tr>
  <tr><td><code>lat_max</code></td><td>90</td><td>Latitude maximale (degrés N)</td></tr>
  <tr><td><code>lon_min</code></td><td>-141</td><td>Longitude ouest (frontière YT/AK)</td></tr>
  <tr><td><code>lon_max</code></td><td>-52</td><td>Longitude est (Terre-Neuve)</td></tr>
</table>
<pre>curl "http://127.0.0.1:5000/north/ais?lat_min=70&lat_max=80&lon_min=-120&lon_max=-80"</pre>
<p>Données retournées : MMSI, nom navire, callsign, type, cap, vitesse, position, flag.</p>

<h3 class="sec">4.2 ADS-B Aviation (OpenSky Network)</h3>
<p>Trafic aérien en zone polaire. Gratuit, sans clé API, source OpenSky Network (UE).</p>
<div class="ok">✅ Aucune inscription requise. Les données sont mises à jour toutes les 10 minutes par le scheduler.</div>
<table>
  <tr><th>Champ retourné</th><th>Description</th></tr>
  <tr><td><code>icao24</code></td><td>Identifiant unique ICAO (mode S transponder)</td></tr>
  <tr><td><code>callsign</code></td><td>Indicatif radio</td></tr>
  <tr><td><code>origin_country</code></td><td>Pays d'immatriculation</td></tr>
  <tr><td><code>altitude_m</code></td><td>Altitude géométrique en mètres</td></tr>
  <tr><td><code>velocity_ms</code></td><td>Vitesse au sol en m/s (×1.944 = noeuds)</td></tr>
  <tr><td><code>on_ground</code></td><td>Vrai si au sol</td></tr>
</table>
<pre>curl "http://127.0.0.1:5000/north/adsb"</pre>

<h3 class="sec">4.3 Satellite Copernicus (Sentinel-1/2/3)</h3>
<p>Recherche de produits satellitaires récents sur l'Arctique canadien. Source : Copernicus Data Space Ecosystem (UE), accès gratuit sans authentification pour la recherche.</p>

<h4 class="sub">Collections disponibles</h4>
<table>
  <tr><th>Satellite</th><th>Type</th><th>Résolution</th><th>Usage Arctique</th><th>Fréquence</th></tr>
  <tr><td>Sentinel-1</td><td>SAR (radar)</td><td>10m</td><td>Glace marine, navires, inondations — pénètre les nuages</td><td>3j</td></tr>
  <tr><td>Sentinel-2</td><td>Optique multispectral</td><td>10m</td><td>Végétation, côtes, glace (limité par couverture nuageuse)</td><td>7j</td></tr>
  <tr><td>Sentinel-3</td><td>OLCI couleur océan</td><td>300m</td><td>Étendue glace, phytoplancton, température surface</td><td>2j</td></tr>
</table>

<h4 class="sub">Recherche par zone prédéfinie (AOI)</h4>
<pre>curl "http://127.0.0.1:5000/north/satellite?aoi=northwest_passage&days=5"</pre>
Zones disponibles : <code>northwest_passage</code> · <code>beaufort_sea</code> · <code>baffin_bay</code> · <code>hudson_bay</code>

<h4 class="sub">Recherche par bbox personnalisée</h4>
<pre>curl "http://127.0.0.1:5000/north/satellite?lat_min=68&lat_max=78&lon_min=-130&lon_max=-100&days=3"</pre>

<h3 class="sec">4.4 Météo nordique (MSC DataMart ECCC)</h3>
<p>Données des 9 stations météo dans les territoires canadiens. Source souveraine canadienne (Environnement et Changement climatique Canada).</p>
<table>
  <tr><th>Code ICAO</th><th>Station</th><th>Province/Territoire</th><th>Position</th></tr>
  <tr><td>CYRB</td><td>Resolute Bay</td><td>Nunavut</td><td>74.7°N 94.9°O</td></tr>
  <tr><td>CYFB</td><td>Iqaluit</td><td>Nunavut</td><td>63.7°N 68.5°O</td></tr>
  <tr><td>CYED</td><td>Edmonton Int'l</td><td>Alberta</td><td>53.3°N 113.6°O</td></tr>
  <tr><td>CYWG</td><td>Winnipeg</td><td>Manitoba</td><td>49.9°N 97.2°O</td></tr>
  <tr><td>CYYZ</td><td>Toronto Pearson</td><td>Ontario</td><td>43.7°N 79.6°O</td></tr>
  <tr><td>CYYC</td><td>Calgary Int'l</td><td>Alberta</td><td>51.1°N 114.0°O</td></tr>
  <tr><td>CYVR</td><td>Vancouver Int'l</td><td>C.-B.</td><td>49.2°N 123.2°O</td></tr>
  <tr><td>CYOW</td><td>Ottawa Macdonald-Cartier</td><td>Ontario</td><td>45.3°N 75.7°O</td></tr>
  <tr><td>CYYJ</td><td>Victoria Int'l</td><td>C.-B.</td><td>48.6°N 123.4°O</td></tr>
</table>
<pre>curl "http://127.0.0.1:5000/north/weather"           # toutes les stations
curl "http://127.0.0.1:5000/north/weather?station=CYRB"  # Resolute Bay seulement</pre>

<h3 class="sec">4.5 Glace marine (CIS/ECCC)</h3>
<p>Le Canadian Ice Service (CIS) publie quotidiennement des cartes de glace marine pour 4 régions. Source souveraine canadienne.</p>
<table>
  <tr><th>Région</th><th>Couverture</th></tr>
  <tr><td>eastern_arctic</td><td>Baie de Baffin, Détroit de Davis</td></tr>
  <tr><td>western_arctic</td><td>Mer de Beaufort, Passage du Nord-Ouest</td></tr>
  <tr><td>hudson_bay</td><td>Baie d'Hudson, Baie de James</td></tr>
  <tr><td>gulf_st_lawrence</td><td>Golfe du Saint-Laurent, Grands Lacs</td></tr>
</table>
<pre>curl "http://127.0.0.1:5000/north/ice"</pre>
<p>Les données incluent la légende de concentration (code WMO egg code, 0–10/10) et les URLs des cartes WMS/WFS du géoservice ECCC.</p>

<h3 class="sec">4.6 Infrastructures critiques (NRCan)</h3>
<p>Cartographie des 19 infrastructures critiques nordiques en 6 catégories. Données combinées NRCan et sources publiques.</p>
<pre>curl "http://127.0.0.1:5000/north/infrastructure?region=all"
curl "http://127.0.0.1:5000/north/infrastructure?region=nunavut"</pre>
Régions : <code>all</code> · <code>nunavut</code> · <code>nwt</code> · <code>yukon</code> · <code>arctic</code>

<h3 class="sec">4.7 Carte Arctique interactive (Folium)</h3>
<p>Carte Leaflet.js générée côté serveur avec fond de carte CartoDB Dark Matter. Affiche les zones AOI satellites, routes maritimes, et positions des stations météo.</p>
<pre>http://127.0.0.1:5000/north/map   # carte HTML complète dans le navigateur</pre>
<div class="note">La carte est générée à chaque requête (pas de cache). Premier rendu : 2–3 secondes.</div>


<!-- ════════════════════════════════════════ -->
<!-- CH. 5 — SCORE DE RISQUE                 -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">5. Score de risque pondéré</h2>

<h3 class="sec">5.1 Formule de calcul</h3>
<p>Le score de risque est calculé pour chaque scan OSINT en appliquant des multiplicateurs au score CVSS de base de chaque finding :</p>
<pre>score_pondéré = CVSS_base × KEV_mult × Age_mult × Context_mult

score_final = 0.6 × max(scores_pondérés) + 0.4 × moyenne(scores_pondérés)
score_final = min(score_final, 10.0)</pre>

<h3 class="sec">5.2 Multiplicateurs contextuels</h3>
<table>
  <tr><th>Multiplicateur</th><th>Valeur</th><th>Déclencheur</th></tr>
  <tr><td>CISA KEV</td><td>×1.5</td><td>Vulnérabilité listée dans le catalogue KEV CISA (exploitée in-the-wild)</td></tr>
  <tr><td>Patch Age</td><td>×1.2</td><td>Correctif disponible depuis plus de 180 jours sans application</td></tr>
  <tr><td>Exposition email</td><td>×1.1</td><td>DMARC absent, SPF softfail, ou DKIM manquant</td></tr>
  <tr><td>Exposé internet</td><td>×1.2</td><td>Service d'administration ou d'infrastructure accessible publiquement</td></tr>
  <tr><td>Sans auth</td><td>×1.3</td><td>Interface sans authentification détectée</td></tr>
  <tr><td>EOL</td><td>×1.1</td><td>Version logicielle hors support officiel du fabricant</td></tr>
</table>

<h3 class="sec">5.3 Grille de notation</h3>
<table>
  <tr><th>Grade</th><th>Score</th><th>Label</th><th>Signification</th></tr>
  <tr><td><span class="badge green">A+</span></td><td>0.0 – 0.9</td><td>EXCELLENT</td><td>Aucun finding critique — posture exemplaire</td></tr>
  <tr><td><span class="badge green">A</span></td><td>1.0 – 2.9</td><td>BON</td><td>Findings mineurs seulement</td></tr>
  <tr><td><span class="badge" style="background:#cfe2ff;color:#084298">B</span></td><td>3.0 – 4.9</td><td>ACCEPTABLE</td><td>Points d'amélioration significatifs</td></tr>
  <tr><td><span class="badge orange">C</span></td><td>5.0 – 6.9</td><td>MOYEN</td><td>Vulnérabilités réelles, action recommandée</td></tr>
  <tr><td><span class="badge" style="background:#ffe5d0;color:#9c4100">D</span></td><td>7.0 – 8.9</td><td>ÉLEVÉ</td><td>Risque significatif, remédiation urgente</td></tr>
  <tr><td><span class="badge red">F</span></td><td>9.0 – 10.0</td><td>CRITIQUE</td><td>Exposition critique, action immédiate</td></tr>
</table>

<h3 class="sec">5.4 Utilisation programmatique</h3>
<pre>from reporting.risk_score import compute_risk_score

scan_data = {{...}}  # données brutes d'un scan
risk = compute_risk_score(scan_data)
print(f"Score : {{risk['score']}}/10  Grade : {{risk['grade']}}")</pre>


<!-- ════════════════════════════════════════ -->
<!-- CH. 6 — RAPPORTS PDF                   -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">6. Génération de rapports PDF</h2>

<h3 class="sec">6.1 Rapport plateforme (scan + Arctique)</h3>
<pre>source .venv/bin/activate
python3 reporting/pdf_report.py --scan-id 4 --out /chemin/rapport.pdf</pre>

<p>Le script collecte automatiquement :</p>
<ul>
  <li>Le scan OSINT spécifié (via <code>--scan-id</code>)</li>
  <li>Les données live de tous les modules Arctique</li>
  <li>Le score de risque pondéré calculé</li>
  <li>Les recommandations priorisées</li>
</ul>

<h3 class="sec">6.2 Sections du rapport PDF</h3>
<table>
  <tr><th>Section</th><th>Contenu</th></tr>
  <tr><td>§1 Architecture</td><td>Inventaire modules, sources souveraines, infra technique</td></tr>
  <tr><td>§2 Score de risque</td><td>Score pondéré, breakdown par catégorie, méthodologie</td></tr>
  <tr><td>§3 Scan OSINT</td><td>DNS, email, SSL, WHOIS, CVE, findings</td></tr>
  <tr><td>§4 Pipeline Arctique</td><td>ADS-B, Satellite, Météo, Infrastructure, Glace</td></tr>
  <tr><td>§5 Recommandations</td><td>Urgences, extensions plateforme, souveraineté</td></tr>
</table>

<h3 class="sec">6.3 Transfert automatique Windows</h3>
<pre>cp rapport.pdf "/media/sf_Kali-share/OSINT 2026/"</pre>
<div class="note">Le dossier partagé VirtualBox <code>sf_Kali-share</code> doit être monté. Vérifier avec : <code>ls /media/sf_Kali-share/</code></div>


<!-- ════════════════════════════════════════ -->
<!-- CH. 7 — API REST                        -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">7. API REST — Référence complète</h2>

<h3 class="sec">7.1 OSINT / TI</h3>
<table>
  <tr><th>Méthode</th><th>Route</th><th>Description</th></tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/</code></td>
    <td>Dashboard HTML (SPA)</td>
  </tr>
  <tr>
    <td><span class="method post">POST</span></td>
    <td><code>/api/scan</code></td>
    <td>Lance un scan. Body JSON : <code>{{"target": "canada.ca", "kind": "domain"}}</code></td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/api/report/&#123;id&#125;</code></td>
    <td>Rapport JSON complet d'un scan</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/api/report/&#123;id&#125;.json</code></td>
    <td>Export JSON brut téléchargeable</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/api/targets</code></td>
    <td>Liste de toutes les cibles scannées</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/api/stats/&#123;target&#125;</code></td>
    <td>Statistiques d'une cible (nb scans, évolution)</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/api/delta?a=&#123;id1&#125;&amp;b=&#123;id2&#125;</code></td>
    <td>Delta entre deux scans (nouvelles vulns, corrections)</td>
  </tr>
</table>

<h3 class="sec">7.2 Pipeline Arctique</h3>
<table>
  <tr><th>Méthode</th><th>Route</th><th>Paramètres</th><th>Source</th></tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/ais</code></td>
    <td>lat_min, lat_max, lon_min, lon_max</td>
    <td>AISHub</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/adsb</code></td>
    <td>lat_min, lat_max, lon_min, lon_max</td>
    <td>OpenSky EU</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/satellite</code></td>
    <td>days=5, aoi=northwest_passage, lat/lon bbox</td>
    <td>Copernicus EU</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/weather</code></td>
    <td>station=CYRB (code ICAO)</td>
    <td>MSC/ECCC CA</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/infrastructure</code></td>
    <td>region=all|nunavut|nwt|yukon|arctic</td>
    <td>NRCan CA</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/ice</code></td>
    <td>Aucun</td>
    <td>CIS/ECCC CA</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/geo</code></td>
    <td>Aucun</td>
    <td>NRCan CA</td>
  </tr>
  <tr>
    <td><span class="method get">GET</span></td>
    <td><code>/north/map</code></td>
    <td>Aucun (rendu HTML)</td>
    <td>Folium offline</td>
  </tr>
</table>

<h3 class="sec">7.3 Exemples curl</h3>
<pre># Scanner un domaine
curl -X POST http://127.0.0.1:5000/api/scan \\
     -H "Content-Type: application/json" \\
     -d '{{"target":"desjardins.com","kind":"domain"}}'

# Obtenir le rapport du scan #1
curl http://127.0.0.1:5000/api/report/1 | python3 -m json.tool

# Satellites Passage du Nord-Ouest, 7 derniers jours
curl "http://127.0.0.1:5000/north/satellite?aoi=northwest_passage&days=7"

# ADS-B restreint à 70-80°N
curl "http://127.0.0.1:5000/north/adsb?lat_min=70&lat_max=80"</pre>


<!-- ════════════════════════════════════════ -->
<!-- CH. 8 — CONFIGURATION AVANCÉE          -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">8. Configuration avancée (.env)</h2>

<h3 class="sec">8.1 Fichier .env complet annoté</h3>
<pre># ── Flask ───────────────────────────────────────────────
FLASK_SECRET_KEY=changez-ceci-en-production-256-bits
FLASK_ENV=production          # development | production
FLASK_HOST=127.0.0.1          # 0.0.0.0 pour exposer sur le réseau
FLASK_PORT=5000               # port d'écoute

# ── Base de données ─────────────────────────────────────
DATABASE_URL=sqlite:///osint.db            # SQLite local
# DATABASE_URL=postgresql://user:pw@localhost/osint  # PostgreSQL

# ── Cache ───────────────────────────────────────────────
CACHE_TTL=3600                # TTL en secondes (1h par défaut)

# ── Collectors OSINT ────────────────────────────────────
ENABLE_DNS=true
ENABLE_HTTP=true
ENABLE_WHOIS=true
ENABLE_CVE=true
CVE_KEYWORD=drupal            # keyword NVD (défaut = 1er label domaine)

ENABLE_URLSCAN=false
URLSCAN_API_KEY=              # https://urlscan.io/user/apikey

ENABLE_SHODAN=false
SHODAN_API_KEY=               # https://account.shodan.io/

ENABLE_CENSYS=false
CENSYS_API_ID=
CENSYS_API_SECRET=            # https://search.censys.io/account/api

# ── Pipeline Arctique ───────────────────────────────────
AISHUB_API_KEY=               # https://www.aishub.net/ (inscription gratuite)
SCHEDULER_ENABLED=true        # false = désactive les tâches de fond</pre>

<h3 class="sec">8.2 Scheduler — Fréquences des tâches</h3>
<table>
  <tr><th>Tâche</th><th>Fréquence</th><th>Description</th></tr>
  <tr><td>AIS maritime</td><td>Toutes les 15 min</td><td>Mise à jour trafic navires Arctique</td></tr>
  <tr><td>ADS-B aviation</td><td>Toutes les 10 min</td><td>Vols actifs zone polaire</td></tr>
  <tr><td>Météo ECCC</td><td>Toutes les 30 min</td><td>9 stations nordiques</td></tr>
  <tr><td>Glace marine CIS</td><td>Toutes les 24h</td><td>Cartes quotidiennes CIS</td></tr>
  <tr><td>Satellite Copernicus</td><td>Toutes les 6h</td><td>Nouveaux produits Sentinel</td></tr>
</table>


<!-- ════════════════════════════════════════ -->
<!-- CH. 9 — SÉCURITÉ                        -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">9. Sécurité et bonnes pratiques</h2>

<h3 class="sec">9.1 Règles fondamentales</h3>
<ul>
  <li><strong>Ne jamais exposer sur Internet sans authentification</strong> — la plateforme n'a pas d'auth intégrée en v2.0</li>
  <li><strong>Changer FLASK_SECRET_KEY</strong> avant tout déploiement (minimum 32 caractères aléatoires)</li>
  <li>Garder <code>FLASK_HOST=127.0.0.1</code> en développement</li>
  <li>Ne jamais committer le fichier <code>.env</code> dans git (déjà dans <code>.gitignore</code>)</li>
  <li>Utiliser uniquement en recon <strong>passive</strong> — aucun scan actif/intrusif</li>
</ul>

<h3 class="sec">9.2 Déploiement sécurisé (production)</h3>
<table>
  <tr><th>Étape</th><th>Action</th></tr>
  <tr><td>1</td><td>Passer derrière un reverse proxy (nginx) avec TLS</td></tr>
  <tr><td>2</td><td>Ajouter une authentification HTTP Basic ou OAuth2 (Flask-Login)</td></tr>
  <tr><td>3</td><td>Utiliser Gunicorn avec 4 workers : <code>gunicorn -w 4 "app:create_app()"</code></td></tr>
  <tr><td>4</td><td>Migrer vers PostgreSQL pour la concurrence</td></tr>
  <tr><td>5</td><td>Activer les headers sécurité (CSP, HSTS, X-Frame) via Flask-Talisman</td></tr>
  <tr><td>6</td><td>Logger les scans et accès (Flask-Logging + rotation)</td></tr>
</table>

<h3 class="sec">9.3 Vulnérabilités actuelles connues (v2.0)</h3>
<table>
  <tr><th>Vuln</th><th>Sévérité</th><th>Description</th><th>Mitigation</th></tr>
  <tr><td>Pas d'authentification</td><td><span class="badge red">CRITIQUE</span></td><td>Tout utilisateur réseau peut accéder à tous les endpoints</td><td>Déployer derrière VPN ou ajouter Flask-Login</td></tr>
  <tr><td>SECRET_KEY faible (défaut)</td><td><span class="badge red">CRITIQUE</span></td><td><code>dev-secret</code> = sessions forgeable en production</td><td>Changer dans .env avant prod</td></tr>
  <tr><td>Pas de rate-limiting</td><td><span class="badge orange">ÉLEVÉ</span></td><td>POST /api/scan illimité = DOS possible</td><td>Ajouter Flask-Limiter</td></tr>
  <tr><td>CORS non configuré</td><td><span class="badge orange">ÉLEVÉ</span></td><td>Toute origine peut appeler l'API</td><td>Ajouter Flask-CORS avec whitelist</td></tr>
  <tr><td>SQLite single-thread</td><td><span class="badge grey">FAIBLE</span></td><td>Race conditions en prod multi-worker</td><td>Migrer vers PostgreSQL</td></tr>
</table>


<!-- ════════════════════════════════════════ -->
<!-- CH. 10 — DÉPANNAGE                      -->
<!-- ════════════════════════════════════════ -->
<div class="pb"></div>
<h2 class="ch">10. Dépannage</h2>

<table>
  <tr><th>Problème</th><th>Cause probable</th><th>Solution</th></tr>
  <tr>
    <td>Port 5000 déjà utilisé</td>
    <td>Un autre service (AirPlay, autre Flask)</td>
    <td><code>FLASK_PORT=5001 python3 app.py</code></td>
  </tr>
  <tr>
    <td>RuntimeError: Working outside application context</td>
    <td>Appel SQLAlchemy dans un thread sans contexte Flask</td>
    <td>Déjà géré — cache.py retourne None silencieusement</td>
  </tr>
  <tr>
    <td>Panel ADS-B vide (0 vols)</td>
    <td>Zone trop restreinte ou pas de vols au moment du scan</td>
    <td>Normal — zone 60-90°N peu fréquentée. Réessayer avec <code>lat_min=50</code></td>
  </tr>
  <tr>
    <td>Satellite "0 produits"</td>
    <td>Copernicus API temporairement indisponible</td>
    <td>Augmenter <code>days=7</code> ou réessayer dans 10min</td>
  </tr>
  <tr>
    <td>CVE collector timeout</td>
    <td>NVD rate-limit (5 req/30s)</td>
    <td>Attendre 30s — le cache évite les appels répétés</td>
  </tr>
  <tr>
    <td>Glace marine "live_status: error"</td>
    <td>URL DataMart ECCC changée</td>
    <td>Les métadonnées statiques restent disponibles — tracking issue ouvert</td>
  </tr>
  <tr>
    <td>WeasyPrint erreur police</td>
    <td>Polices DejaVu non installées</td>
    <td><code>sudo apt install fonts-dejavu</code></td>
  </tr>
  <tr>
    <td>Scheduler APScheduler erreur au démarrage</td>
    <td>Port ou thread conflict</td>
    <td><code>SCHEDULER_ENABLED=false</code> pour désactiver</td>
  </tr>
</table>

<div style="margin-top:30px;text-align:center;font-size:7pt;color:#aaa;border-top:1px solid #eee;padding-top:10px">
  Sentinelle Nord Canada v{VERSION} — Manuel généré le {now}<br>
  Contact : roblehassanabdi@gmail.com
</div>

</body>
</html>"""


def main():
    from datetime import date
    today = date.today().isoformat()
    parser = argparse.ArgumentParser(description="Manuel Sentinelle Nord Canada")
    parser.add_argument("--out", default=f"/home/kali/OSINT_Reports/Sentinelle-Manuel-{today}.pdf")
    args = parser.parse_args()

    print("Génération HTML du manuel…")
    html = build_manual_html()

    print("Rendu PDF WeasyPrint…")
    from weasyprint import HTML
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(BASE_DIR)).write_pdf(str(out_path))

    size_kb = out_path.stat().st_size // 1024
    print(f"Manuel PDF généré : {out_path} ({size_kb} KB)")
    return str(out_path)


if __name__ == "__main__":
    main()
