# Nmap

#### Introduction

Nmap (Network Mapper) est un outil puissant pour la découverte de réseaux et l’audit de sécurité. Il permet de scanner des réseaux pour découvrir des hôtes actifs, des services ouverts, des systèmes d'exploitation et bien plus encore.

#### Installation de Nmap

**Sous Linux**

```bash
sudo apt-get install nmap    # Pour les distributions basées sur Debian/Ubuntu
```

#### Commandes de Base

1.  **Scan de base**

    ```bash
    nmap <IP ou domaine>
    ```

    * **Explication** : Effectue un scan par défaut pour découvrir les hôtes actifs et les services ouverts sur l'adresse IP ou le domaine spécifié.


2.  **Scan de plusieurs hôtes**

    ```bash
    nmap 192.168.1.1 192.168.1.2 192.168.1.3
    nmap 192.168.1.1-10
    ```

    * **Explication** : Permet de scanner plusieurs adresses IP à la fois, soit en les listant individuellement, soit en spécifiant une plage d'adresses.


3.  **Scan d'une plage d'adresses IP**

    ```bash
    nmap 192.168.1.0/24
    ```

    * **Explication** : Scanne une sous-réseau complet en utilisant la notation CIDR (Classless Inter-Domain Routing).
    * **Discrétion** : Faible à moyenne. Le scan de tout un sous-réseau peut être très visible.
4.  **Scan de ports spécifiques**

    ```bash
    nmap -p 22,80,443 <IP>
    ```

    * **Explication** : Limite le scan à des ports spécifiques (par exemple, les ports 22, 80, et 443).


5.  **Scan de tous les ports**

    ```bash
    nmap -p- <IP>
    ```

    * **Explication** : Scanne tous les ports TCP disponibles (de 1 à 65535).



#### Types de Scans

1.  **Scan SYN (scan par défaut, nécessite des privilèges root)**

    ```bash
    sudo nmap -sS <IP>
    ```

    * **Explication** : Effectue un scan SYN, souvent appelé "demi-ouvert", car il n'établit pas de connexion complète. Ce scan est rapide et discret.


2.  **Scan de connectivité TCP (n'exige pas de privilèges root)**

    ```bash
    nmap -sT <IP>
    ```

    * **Explication** : Effectue un scan de connectivité TCP complet en établissant des connexions complètes avec les ports cibles. Moins discret mais ne nécessite pas de privilèges root.


3.  **Scan UDP**

    ```bash
    sudo nmap -sU <IP>
    ```

    * **Explication** : Scanne les ports UDP. Ce type de scan est plus lent et peut générer beaucoup de faux positifs.


4.  **Scan pour la détection des versions des services**

    ```bash
    nmap -sV <IP>
    ```

    * **Explication** : Interroge les services sur les ports ouverts pour déterminer les versions des logiciels en cours d'exécution.


5.  **Scan de détection du système d'exploitation**

    ```bash
    sudo nmap -O <IP>
    ```

    * **Explication** : Utilise diverses techniques pour déterminer le système d'exploitation en cours d'exécution sur l'hôte cible.


6.  **Scan de scripts Nmap (NSE - Nmap Scripting Engine)**

    ```bash
    nmap --script <script-name> <IP>
    nmap --script vuln <IP>    # Pour détecter les vulnérabilités
    ```

    * **Explication** : Exécute des scripts NSE pour automatiser des tâches spécifiques comme la détection de vulnérabilités, la collecte d'informations, etc.



#### Options Avancées

1.  **Fragmentation des paquets (`-f`)**

    ```bash
    sudo nmap -f <IP>
    ```

    * **Explication** : Fragmente les paquets envoyés en plus petits segments pour contourner certains pare-feu et IDS.


2.  **Spécification de la taille des fragments**

    ```bash
    sudo nmap --mtu 24 <IP>
    ```

    * **Explication** : Permet de spécifier la taille de l'unité de transmission maximale (MTU) pour les fragments. Cela peut rendre les paquets encore plus difficiles à analyser pour les pare-feu.


3.  **Scan furtif SYN avec fragmentation**

    ```bash
    sudo nmap -sS -f <IP>
    ```

    * **Explication** : Combine un scan SYN furtif avec la fragmentation des paquets pour une meilleure évasion des IDS.


4.  **Utilisation de fausses adresses IP sources (`-D`)**

    ```bash
    sudo nmap -D RND:10 <IP>
    ```

    * **Explication** : Utilise des adresses IP sources fictives (10 adresses aléatoires dans cet exemple) pour masquer l'origine réelle du scan.


5.  **Scan aléatoire des ports (`-r`)**

    ```bash
    nmap -r <IP>
    ```

    * **Explication** : Scanne les ports dans un ordre aléatoire pour éviter la détection par les systèmes de surveillance basés sur les modèles de scan.


6.  **Scan avec temporisation lente (`-T0` à `-T5`)**

    ```bash
    sudo nmap -sS -T0 <IP>
    ```

    * **Explication** : Utilise un timing très lent (`-T0` étant le plus lent) pour rendre le scan moins détectable. Les niveaux de temporisation vont de `-T0` (paranoid) à `-T5` (insane).


7.  **Modification des tailles de paquets TCP (`--data-length`)**

    ```bash
    sudo nmap --data-length 50 <IP>
    ```

    * **Explication** : Ajoute des données aléatoires aux paquets pour modifier leur taille et contourner les IDS/IPS.


8.  **Modification des adresses MAC (`--spoof-mac`)**

    ```bash
    sudo nmap --spoof-mac <mac_address> <IP>
    ```

    * **Explication** : Modifie l'adresse MAC source pour tromper les pare-feu basés sur l'adresse MAC.


9.  **Utilisation de decoy hosts (`-D`)**

    ```bash
    sudo nmap -D decoy1,decoy2,decoy3 <IP>
    ```

    * **Explication** : Utilise des hôtes leurres pour masquer l'origine du scan.



#### Exemples de Scénarios d'Évasion

1.  **Scan furtif et fragmenté pour contourner les IDS**

    ```bash
    sudo nmap -sS -f <IP>
    ```

    * **Explication** : Combine un scan SYN furtif avec la fragmentation des paquets pour une meilleure évasion des IDS.


2.  **Scan avec fausses adresses IP sources et temporisation lente**

    ```bash
    sudo nmap -sS -D RND:10 -T0 <IP>
    ```

    * **Explication** : Utilise des adresses IP sources fictives et un timing très lent pour masquer l'origine du scan et éviter la détection.


3.  **Scan avec modification de la taille des paquets TCP et adresses MAC spoofées**

    ```bash
    sudo nmap --data-length 50 --spoof-mac 0A:12:34:56:78:9A <IP>
    ```

    * **Explication** : Ajoute des données aléatoires aux paquets et modifie l'adresse MAC source pour contourner les pare-feu.



| Type d'analyse des ports               | Exemple de commande                                   |
| -------------------------------------- | ----------------------------------------------------- |
| Analyse TCP nulle                      | `sudo nmap -sN MACHINE_IP`                            |
| Analyse TCP FIN                        | `sudo nmap -sF MACHINE_IP`                            |
| Scan de Noël TCP                       | `sudo nmap -sX MACHINE_IP`                            |
| Analyse TCP Maimon                     | `sudo nmap -sM MACHINE_IP`                            |
| Analyse TCP ACK                        | `sudo nmap -sA MACHINE_IP`                            |
| Analyse de la fenêtre TCP              | `sudo nmap -sW MACHINE_IP`                            |
| Analyse TCP personnalisée              | `sudo nmap --scanflags URGACKPSHRSTSYNFIN MACHINE_IP` |
| IP source usurpée                      | `sudo nmap -S SPOOFED_IP MACHINE_IP`                  |
| Adresse MAC usurpée                    | `--spoof-mac SPOOFED_MAC`                             |
| Scan de leurre                         | `nmap -D DECOY_IP,ME MACHINE_IP`                      |
| Scan inactif ( zombie )                | `sudo nmap -sI ZOMBIE_IP MACHINE_IP`                  |
| Fragmenter les données IP en 8 octets  | `-f`                                                  |
| Fragmenter les données IP en 16 octets | `-ff`                                                 |

| Option                   | But                                                              |
| ------------------------ | ---------------------------------------------------------------- |
| `--source-port PORT_NUM` | spécifier le numéro de port source                               |
| `--data-length NUM`      | ajouter des données aléatoires pour atteindre la longueur donnée |

Ces types d'analyse s'appuient sur la définition d'indicateurs TCP de manière inattendue pour inciter les ports à répondre. Les analyses Null, FIN et Xmas provoquent une réponse des ports fermés, tandis que les analyses Maimon, ACK et Window provoquent une réponse des ports ouverts et fermés.

| Option     | But                                              |
| ---------- | ------------------------------------------------ |
| `--reason` | explique comment Nmap est arrivé à sa conclusion |
| `-v`       | verbeux                                          |
| `-vv`      | très verbeux                                     |
| `-d`       | débogage                                         |
| `-dd`      | plus de détails pour le débogage                 |

SCRIPTS

| Catégorie de scénario | Description                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------ |
| `auth`                | Scripts liés à l'authentification                                                                |
| `broadcast`           | Découvrez les hôtes en envoyant des messages de diffusion                                        |
| `brute`               | Effectue un audit de mot de passe par force brute sur les connexions                             |
| `default`             | Scripts par défaut, identiques à`-sC`                                                            |
| `discovery`           | Récupérer des informations accessibles, telles que des tables de base de données et des noms DNS |
| `dos`                 | Détecte les serveurs vulnérables au déni de service ( DoS )                                      |
| `exploit`             | Tentatives d'exploitation de divers services vulnérables                                         |
| `external`            | Vérifications à l'aide d'un service tiers, tel que Geoplugin et Virustotal                       |
| `fuzzer`              | Lancer des attaques de fuzzing                                                                   |
| `intrusive`           | Scripts intrusifs tels que les attaques par force brute et l'exploitation                        |
| `malware`             | Recherche de portes dérobées                                                                     |
| `safe`                | Des scripts sûrs qui ne feront pas planter la cible                                              |
| `version`             | Récupérer les versions de service                                                                |
| `vuln`                | Vérifie les vulnérabilités ou exploite les services vulnérables                                  |



OPTIONS

| Option                    | Signification                                                        |
| ------------------------- | -------------------------------------------------------------------- |
| `-sV`                     | déterminer les informations de service/version sur les ports ouverts |
| `-sV --version-light`     | essayez les sondes les plus probables (2)                            |
| `-sV --version-all`       | essayer toutes les sondes disponibles (9)                            |
| `-O`                      | détecter le système d'exploitation                                   |
| `--traceroute`            | exécuter traceroute vers la cible                                    |
| `--script=SCRIPTS`        | Scripts Nmap à exécuter                                              |
| `-sC`ou`--script=default` | exécuter les scripts par défaut                                      |
| `-A`                      | équivalent à`-sV -O -sC --traceroute`                                |
| `-oN`                     | enregistrer la sortie au format normal                               |
| `-oG`                     | enregistrer la sortie dans un format grepable                        |
| `-oX`                     | enregistrer la sortie au format XML                                  |
| `-oA`                     | enregistrer la sortie aux formats normal, XML et Grepable            |
