import ipaddress
from functions import *

while True:
    nettoyer_ecran()
    afficher_banniere()
    
    print("IP TOOL - MENU PRINCIPAL")
    print("-" * 30)
    print("1. Bloquer une adresse IP (Blacklist)")
    print("2. Analyser avec VirusTotal (API) / AbuseIPDB / Cisco Talos")
    print("3. Geolocalisation d'IP")
    print("4. Consulter la Blacklist")
    print("5. Extraire des IP d'un fichier HTML")
    print("6. Quitter le programme")
    print("-" * 30)
    
    choix = input("Faites votre choix (1-6) : ")

    match choix:
        
        case "1" | "2" | "3":
            ip_saisie = input("\nEntrez l'adresse IP a traiter : ")
            
            try:
                ipaddress.ip_address(ip_saisie)
                
                if choix == "1":
                    bloquer_ip(ip_saisie)
                elif choix == "2":
                    analyseDesIP(ip_saisie)
                elif choix == "3":
                    geolocaliser_ip(ip_saisie)    
                    
                    
            except ValueError:
                print(f"\n[ERREUR] '{ip_saisie}' n'est pas une adresse IPv4 ou IPv6 valide.")
            
            input("\nAppuyez sur Entree pour revenir au menu...")

        case "4":
            consulter_blacklist()
            input("\nAppuyez sur Entree pour revenir au menu...")

        case "5":
            nom_f = input("\nEntrez le nom du fichier HTML a analyser (ex: test.html) : ")
            extraire_ip_html(nom_f)
            input("\nAppuyez sur Entree pour revenir au menu...")

        case "6":
            print("\nFermeture de l'outil. Securisez bien votre reseau !")
            break

        case _:
            print("\n[ERREUR] Choix non reconnu. Veuillez taper un chiffre entre 1 et 6.")
            input("\nAppuyez sur Entree pour reessayer...")