import os
import re
from dotenv import load_dotenv
import requests
import ipaddress 


def nettoyer_ecran():
    """Efface le contenu du terminal selon le système d'exploitation."""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def afficher_banniere():
    """Affiche le titre du projet."""
    print("-" * 50)
    print("""
  _____ _____    _______ ____   ____  _      
 |_   _|  __ \  |__   __/ __ \ / __ \| |     
   | | | |__) |    | | | |  | | |  | | |     
   | | |  ___/     | | | |  | | |  | | |     
  _| |_| |         | | | |__| | |__| | |____ 
 |_____|_|         |_|  \____/ \____/|______|
    """)
    print("       Version 1.0 - Outil de gestion d'adresses IP")
    print("-" * 50)


def geolocaliser_ip(ip_a_traiter):
    url = f"http://ip-api.com/json/{ip_a_traiter}"
    print(f"\n[SCAN] Localisation de l'IP : {ip_a_traiter}...")
    try:
        reponse = requests.get(url)
        data = reponse.json()
        if data['status'] == 'success':
            print(f" -> Localisation : {data['city']}, {data['country']}")
            print(f" -> Fournisseur : {data['isp']}")
            print(f" -> Latitude : {data['lat']}, Longitude : {data['lon']}")
        else:
            print(" -> Impossible de localiser cette IP (IP privée ou invalide).")
    except Exception as e:
        print(f" -> [ERREUR] Connexion impossible : {e}")    

def bloquer_ip(ip_a_traiter):
    """Vérifie et ajoute une IP au fichier blacklist.txt."""
    print(f"\n[ACTION] Verification de l'IP : {ip_a_traiter}")
    
    if not os.path.exists("blacklist.txt"):
        open("blacklist.txt", "w").close()

    with open("blacklist.txt", "r") as f:
        contenu = f.read()

    if ip_a_traiter in contenu:
        print(f"RESULTAT : L'IP {ip_a_traiter} est deja presente dans la liste.")
    else:
        with open("blacklist.txt", "a") as f:
            f.write(ip_a_traiter + "\n")
            print(f"RESULTAT : L'IP {ip_a_traiter} a ete ajoutee avec succes.")

def consulter_blacklist():

    if not os.path.exists("blacklist.txt"):
        print("\n[INFO] La blacklist est vide (le fichier n'existe pas encore).")
        return 

    print("\n--- LISTE DES IP BLOQUÉES ---")
    with open("blacklist.txt", "r") as f:
      
        lignes = f.readlines() 
        
        if not lignes:
            print("La liste est actuellement vide.")
        else:
            for ligne in lignes:
                
                print(f"- {ligne.strip()}")
    print("-" * 30)   

def extraire_ip_html(nom_fichier):
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r") as f_source:
            contenu = f_source.read()
        
        
        motif = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        potentiels = re.findall(motif, contenu)
        
        ips_valides = [] 

       
        for truc in potentiels:
            try:
                ip_propre = ipaddress.ip_address(truc)
                ips_valides.append(str(ip_propre))
            except ValueError:
                continue 

        ips_finales = list(set(ips_valides))

        with open("IpATraiter.txt", "w") as f_dest:
            for ip in ips_finales:
                f_dest.write(ip + "\n")
        
        print(f"\n[SUCCES] Extraction terminee. {len(ips_finales)} IP valides enregistrees.")
        
        print("\n--- IP REELLES TROUVEES ---")
        print(" Consultez IpATraiter.txt pour la liste complete.")
        for ip in ips_finales:
            print(f" -> {ip}")
            
            
    else:
        print(f"\n[ERREUR] Le fichier '{nom_fichier}' est introuvable.")


load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

def analyseDesIP(ip_a_traiter):
    """Analyse une IP avec VirusTotal, AbuseIPDB."""
    print(f"\n[INFO] Analyse de l'IP : {ip_a_traiter}")
    print("[INFO] Analyse VirusTotal...")
    print("[INFO] Analyse AbuseIPDB...")

    url_vt = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_a_traiter}"
    headers_vt = {"x-apikey": VT_KEY}
    
    reponse_vt = requests.get(url_vt, headers=headers_vt)
    
    if reponse_vt.status_code == 200:
        data = reponse_vt.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        print(f" -> VirusTotal : {malicious} moteurs ont detecte cette IP comme malveillante.")
    else:
        print(f" -> VirusTotal : Erreur {reponse_vt.status_code}")


    url_abuse = "https://api.abuseipdb.com/api/v2/check"
    params_abuse = {'ipAddress': ip_a_traiter, 'maxAgeInDays': '90'}
    headers_abuse = {
        'Accept': 'application/json',
        'Key': ABUSE_KEY
    }

    reponse_abuse = requests.get(url_abuse, headers=headers_abuse, params=params_abuse)

    if reponse_abuse.status_code == 200:
        data_abuse = reponse_abuse.json()
        score = data_abuse['data']['abuseConfidenceScore']
        print(f" -> AbuseIPDB : Score de suspicion de {score}%")
    else:
        print(f" -> AbuseIPDB : Erreur {reponse_abuse.status_code}")    

 
   