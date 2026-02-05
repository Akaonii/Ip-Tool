# IP TOOL

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![OSINT](https://img.shields.io/badge/OSINT-Security-red)
![APIs](https://img.shields.io/badge/APIs-VT%20%7C%20AbuseIPDB-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**IP TOOL** est un utilitaire en ligne de commande conçu pour les administrateurs système et les analystes en cybersécurité. Il permet de gérer des listes noires locales, de géolocaliser des adresses et d'évaluer la dangerosité des connexions via des services tiers.

L'outil automatise l'analyse de réputation en interrogeant les APIs de **VirusTotal** et **AbuseIPDB** pour fournir un score de risque immédiat et précis.

---

## 📸 Screenshot

![IP TOOL](./iptool.png)

---

## ✨ Features

* **🛡️ Gestion de Blacklist** : Ajout sécurisé d'adresses IP dans un fichier `blacklist.txt` avec détection automatique des doublons.
* **🔍 Analyse Multi-API** : Récupération du nombre de détections malveillantes sur VirusTotal et du score de suspicion sur AbuseIPDB.
* **🌍 Géolocalisation Live** : Identification du pays, de la ville, de l'ISP (fournisseur) et des coordonnées GPS via l'API ip-api.
* **📄 Extracteur HTML** : Scan automatique de fichiers (ex: `test.html`) pour extraire toutes les adresses IPv4 valides et les sauvegarder dans `IpATraiter.txt`.
* **💻 Expérience Console** : Interface fluide avec nettoyage d'écran automatisé pour Windows (`cls`) et Linux/Mac (`clear`).

---

## 🛠 Tech Stack

* **Backend** : Python 3.11+
* **Libraries** : `requests`, `python-dotenv`, `re`
* **External APIs** : VirusTotal v3, AbuseIPDB v2, IP-API

---

## 🚀 How to run

### 1. Cloner le projet

bash

git clone [https://github.com/Akaonii/Ip-Tool.git](https://github.com/Akaonii/Ip-Tool.git)
cd Ip-Tool

2. Installation des dépendances
   
Bash
pip install requests python-dotenv

4. Configuration des clés API
   
Créez un fichier .env à la racine du dossier et ajoutez vos identifiants :

Extrait de code

VT_API_KEY=votre_cle_virustotal

ABUSEIPDB_API_KEY=votre_cle_abuseipdb

5. Lancer l'application

Bash

python main.p

📄 License
Distribué sous la licence MIT. Voir le fichier LICENSE pour plus d'informations.

