Projet Réseau & Cybersécurité : Déploiement d'une Architecture Multi-Zones Sécurisée (LAN, DMZ, Internet)

Ce projet détaille la conception, l'interconnexion, le cloisonnement et le filtrage d'un réseau d'entreprise complet sous Cisco Packet Tracer. 
Le scénario intègre un poste compromis en interne et démontre la mise en œuvre de la sécurité en profondeur (défense niveau 2 sur commutateur, pare-feu sans état via routeur et pare-feu d'état dédié Cisco ASA).  
1. Topologie & Plan d'Adressage IPLe réseau repose sur trois zones distinctes reliées exclusivement à travers l'équipement pare-feu. 
Matrice d'adressageZone Interne (LAN) : 192.168.1.0/24 (Passerelle : 192.168.1.1)   
PC-Admin : 192.168.1.10/24 (DNS : 192.168.56.10)   
PC-Infecte : 192.168.1.15/24 (DNS : 192.168.56.10)  
Zone Démilitarisée (DMZ) : 192.168.56.0/24 (Passerelle : 192.168.56.1)  
Srv-Web-Mail : 192.168.56.10/24 (Héberge HTTP, DNS local, SMTP/POP3)  
Lien d'Interconnexion WAN : 203.0.113.0/29 (Sous-réseau point-à-point)  
Interface externe Pare-feu : 203.0.113.1/29  
Interface FAI (ISP-Internet) : 203.0.113.2/29  
Internet simulé : 8.8.8.0/24  
Passerelle FAI : 8.8.8.1/24  
Srv-Internet (Web public) : 8.8.8.8/24  
2. Sécurité d'Accès Niveau 2 (Commutateur SW-LAN Cisco 2960)Dans un même sous-réseau IP (192.168.1.0/24), les trames commutées ne traversent pas la passerelle. Le pare-feu ne peut donc pas stopper les attaques directes entre machines du même segment.
Deux mécanismes de niveau 2 ont été déployés pour combler cette vulnérabilité :  
A. Isolation intra-VLAN (Protected Ports)Principe : Deux interfaces configurées en protected ne peuvent s'échanger aucune trame en local, 
tout en conservant la possibilité de dialoguer avec les ports non protégés (notamment la liaison montante uplink vers le pare-feu).  
Application : Isolation complète entre PC-Admin (port Fa0/2) et PC-Infecte (port Fa0/3). 
La compromission du PC infecté ne lui permet aucun mouvement latéral direct vers le poste administrateur.   
B. Contrôle d'accès physique (Port-Security)Principe : Association stricte de l'adresse MAC légitime à l'interface d'accès.
En cas de débranchement du câble pour y relier un équipement pirate, l'interface bascule en état d'erreur et se coupe immédiatement (err-disabled). 
Commandes appliquées sur SW-LANCisco CLIenable

configure terminal
hostname SW-LAN
no ip domain-lookup

! Sécurisation du port PC-Admin
interface FastEthernet0/2
 description PC-Admin 192.168.1.10
 switchport mode access
 switchport port-security
 switchport port-security maximum 1
 switchport port-security mac-address <MAC_PC_ADMIN>
 switchport port-security violation shutdown
 switchport protected
 exit! 

Sécurisation du port PC-Infecte
interface FastEthernet0/3
 description PC-Infecte 192.168.1.15
 switchport mode access
 switchport port-security
 switchport port-security maximum 1
 switchport port-security mac-address <MAC_PC_INFECTE>
 switchport port-security violation shutdown
 switchport protected
 exit! 
Uplink vers le Firewall (non protégé pour assurer la sortie)
interface FastEthernet0/1
 description Uplink vers Firewall
 exit
end
write memory

   3. Implémentation V1 : Pare-feu sur Routeur Cisco 2911 (Filtrage Stateless & PAT)Dans cette première phase, le filtrage et la translation sont gérés par un routeur Cisco 2911 doté de 3 interfaces GigabitEthernet.  
A. Translation d'Adresses (NAT / PAT Overload)Le réseau LAN privé (192.168.1.0/24) est translaté dynamiquement derrière l'adresse publique du port WAN (203.0.113.1).  
Cloisonnement DMZ : La DMZ n'est volontairement pas ajoutée à la liste NAT. Privée d'adresse routable sur Internet et de translation, elle ne peut pas émettre sur le WAN.  
B. Règles de Filtrage par ACL Étendues (avec masques génériques / wildcards)Trois listes de contrôle d'accès sont appliquées en entrée (in) sur chaque interface afin d'intercepter les paquets au plus tôt :   LAN-IN (sur GigabitEthernet0/1 in) :
Règle 1 : Interdiction explicite de PC-Infecte (192.168.1.15) vers la DMZ (192.168.56.0/24).  
Règle 2 : Autorisation intégrale pour PC-Admin (192.168.1.10) vers la DMZ.  
Règle 3 à 7 : Limitation des autres postes du LAN aux seuls services essentiels de la DMZ (Web : ports 80/443, Mail : ports 25/110, DNS : port 53).  
Règle 8 : Refus de tout autre trafic LAN vers la DMZ (deny ip ...).  
Règle 9 : Autorisation de sortie vers Internet pour tout le réseau interne.   DMZ-IN (sur GigabitEthernet0/2 in) :Autorise la DMZ à renvoyer uniquement les réponses TCP déjà ouvertes (established), les réponses DNS et les messages ICMP autorisés (echo-reply, unreachable) vers le LAN.  
Bloque tout le reste (deny ip any any). La DMZ ne peut initier aucune session vers le réseau local ni vers Internet. En cas de compromission du serveur web, l'attaquant reste confiné dans la DMZ. 
OUTSIDE-IN (sur GigabitEthernet0/0 in) :Autorise uniquement les flux retours des requêtes légitimement initiées par le LAN (established, retours DNS, echo-reply). 
Bloque tout trafic entrant arbitraire provenant d'Internet.   

Commandes clés du Pare-feu RouteurCisco CLI! Routage par défaut et NAT
ip route 0.0.0.0 0.0.0.0 203.0.113.2
access-list 1 permit 192.168.1.0 0.0.0.255
ip nat inside source list 1 interface GigabitEthernet0/0 overload! 

Application des ACLs
interface GigabitEthernet0/1
 ip access-group LAN-IN in
interface GigabitEthernet0/2
 ip access-group DMZ-IN in
interface GigabitEthernet0/0
 ip access-group OUTSIDE-IN in

   4. Implémentation V2 : Pare-feu Dédié Cisco ASA 5506-X (Filtrage Stateful)Dans la version 2, le routeur est remplacé par un pare-feu professionnel Cisco ASA 5506-X.  
A. Différences Architecturales vs RouteurNiveaux de Sécurité (security-level) : L'ASA applique par défaut le principe de confiance décroissante :inside (Niveau 100 - Confiance maximale)   
dmz (Niveau 50 - Confiance intermédiaire)   outside (Niveau 0 - Aucune confiance)  
Le trafic d'un niveau supérieur vers un niveau inférieur est autorisé par défaut, tandis que le trafic inverse est automatiquement bloqué sans règle explicite. 
Inspection d'État (Stateful) : L'ASA surveille les tables de connexion (TCP/UDP) et autorise dynamiquement le trafic retour sans exiger la clause manuelle established.  
Syntaxe réseau : L'ASA requiert des masques de sous-réseau conventionnels (ex: 255.255.255.0) et non des masques inversés (wildcards).   
B. Spécificités & Ajustements TechniquesInspection ICMP : Par défaut, l'ASA ne conserve pas l'état des requêtes ping ICMP (les paquets retour sont rejetés). Il est impératif d'intégrer inspect icmp dans la politique globale (global_policy).  
Contournement du Proxy-ARP : Dans Packet Tracer, si deux ports protégés du switch tentent de communiquer, l'ASA peut répondre à la requête ARP et relayer le trafic en local. Une règle explicite deny ip 192.168.1.0 255.255.255.0 192.168.1.0 255.255.255.0 a été ajoutée dans INSIDE-IN pour garantir l'étanchéité interne.
NAT Objet :Cisco CLIobject network LAN
 subnet 192.168.1.0 255.255.255.0
 nat (inside, outside) dynamic interface




<img width="689" height="704" alt="image" src="https://github.com/user-attachments/assets/6107d06e-de3e-47b8-83bf-6adb66a341f9" />


   5. Synthèse Comparée des TechnologiesCaractéristiqueRouteur Cisco 2911 (V1)Pare-feu Cisco ASA 5506-X (V2)PhilosophieRoutage avec filtrage par interface physique 
Zones logiques (nameif) et niveaux de confiance (0 à 100)  
Gestion du retour de fluxStateless : règles manuelles obligatoires (established, echo-reply)  
Stateful : suivi automatique des sessions en table d'état 
Format des masquesMasques inversés / Wildcards (0.0.0.255)   Masques de sous-réseau conventionnels (255.255.255.0)
Comportement au rejetRenvoie un message ICMP (Destination host unreachable)   Rejet silencieux / Drop (affiche Request timed out, plus furtif) 
Gestion du protocole ICMPAutorisé par défaut ou via règles de liste standard   Doit être inspecté explicitement via inspect icmp   6. Cahier de Recette & Validation des TestsTest de SécuritéCommande exécutéeRésultat V1 (Routeur)Résultat V2 (ASA)Justification Technique
1. Admin vers DMZping 192.168.56.10 / HTTPSuccès   Succès   Autorisé dans LAN-IN / INSIDE-IN.  
2. Admin vers Internetping 8.8.8.8Succès   Succès   Translation NAT/PAT active sur l'interface WAN.  
3. Admin vers PC-Infectéping 192.168.1.15Bloqué (Timeout)   Bloqué (Timeout)   Isolation matérielle assurée par les ports protégés du switch.   
4. PC-Infecté vers DMZping 192.168.56.10Bloqué (Host unreachable)   Bloqué (Timeout)   Interdiction stricte de l'hôte .15 dans l'ACL d'entrée.  
5. PC-Infecté vers Internetping 8.8.8.8Succès   Succès   Conforme au scénario (maintien de l'accès sortant externe).  
6. DMZ vers Internetping 8.8.8.8Bloqué (Unreachable)   Bloqué (Timeout)   Pas de règle NAT et rejet explicite dans l'ACL de la DMZ. 
7. Internet vers Entrepriseping 203.0.113.1Bloqué (Timeout)   Bloqué (Timeout)   Aucun flux initié de l'extérieur n'est accepté.   




<img width="2552" height="1395" alt="image" src="https://github.com/user-attachments/assets/9a0f6168-190f-4165-ac2a-5cdfd71016d9" />

[PKT 2.pdf](https://github.com/user-attachments/files/33227182/PKT.2.pdf)
[PKT.pdf](https://github.com/user-attachments/files/33227176/PKT.pdf)
