# Nmap

## Nmap - Guide Complet pour l'Analyse et l'Audit de Réseaux

***

### Introduction

**Nmap** est un outil incontournable pour les administrateurs systèmes, les pentesters et les chercheurs en cybersécurité. Il est utilisé pour :

* Explorer des réseaux et identifier des hôtes.
* Scanner les ports ouverts et détecter les services.
* Auditer les systèmes pour identifier des vulnérabilités.

***

### 🚀 Étape 1 : Installation de Nmap

***

#### Installation sur Linux

**1. Installer depuis les dépôts (Debian/Ubuntu)**

```bash
sudo apt update
sudo apt install nmap
```

**2. Vérifier l’installation**

```bash
nmap --version
```

> Si cette commande affiche la version de Nmap, l’installation a réussi.

***

#### Installation sur macOS

1.  **Installer Homebrew** (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  **Installer Nmap via Homebrew** :

    ```bash
    brew install nmap
    ```
3.  **Vérifier l’installation** :

    ```bash
    nmap --version
    ```

***

#### Installation sur Windows

1. Téléchargez l'installeur depuis le site officiel : https://nmap.org/download.html.
2. Installez-le en suivant les instructions à l’écran.
3.  Lancez une invite de commande et testez avec :

    ```cmd
    nmap --version
    ```

***

### 🚀 Étape 2 : Types de Scans et Commandes

***

#### 1. Scans TCP Standards

| **Type de Scan**                          | **Commande**               | **Description**                                                 |
| ----------------------------------------- | -------------------------- | --------------------------------------------------------------- |
| **SYN Scan** (rapide)                     | `sudo nmap -sS MACHINE_IP` | Identifie les ports ouverts sans établir de connexion complète. |
| **Scan Connect**                          | `sudo nmap -sT MACHINE_IP` | Établit une connexion complète pour scanner les ports.          |
| **Scan UDP**                              | `sudo nmap -sU MACHINE_IP` | Scanne les ports UDP au lieu de TCP.                            |
| **Scan des 1000 ports les plus courants** | `nmap MACHINE_IP`          | Par défaut, scanne les 1000 ports les plus courants en TCP.     |

***

#### 2. Scans Spécialisés

| **Type de Scan**   | **Commande**               | **Description**                                      |
| ------------------ | -------------------------- | ---------------------------------------------------- |
| **Scan Nulle**     | `sudo nmap -sN MACHINE_IP` | N'envoie aucun indicateur TCP (stealth scan).        |
| **Scan FIN**       | `sudo nmap -sF MACHINE_IP` | Envoie un paquet TCP avec le drapeau FIN activé.     |
| **Scan Xmas**      | `sudo nmap -sX MACHINE_IP` | Envoie plusieurs indicateurs TCP (XMAS tree scan).   |
| **Scan ACK**       | `sudo nmap -sA MACHINE_IP` | Vérifie les règles du pare-feu (filtrage des ports). |
| **Scan Fragmenté** | `sudo nmap -f MACHINE_IP`  | Divise les paquets pour contourner certains IDS.     |

***

#### 3. Scans d’Usurpation et d’Obfuscation

| **Option**         | **Commande**                          | **Description**                                         |
| ------------------ | ------------------------------------- | ------------------------------------------------------- |
| **IP usurpée**     | `sudo nmap -S SPOOFED_IP MACHINE_IP`  | Simule une IP source différente pour masquer l’origine. |
| **Scan de leurre** | `sudo nmap -D DECOY_IP,ME MACHINE_IP` | Ajoute des leurres pour compliquer l’analyse des logs.  |
| **Scan inactif**   | `sudo nmap -sI ZOMBIE_IP MACHINE_IP`  | Utilise une machine zombie pour effectuer le scan.      |

***

#### 4. Détection des Services et OS

| **Option**               | **Commande**              | **Description**                                            |
| ------------------------ | ------------------------- | ---------------------------------------------------------- |
| **Version des services** | `nmap -sV MACHINE_IP`     | Identifie les versions des services en cours d'exécution.  |
| **Détection OS**         | `sudo nmap -O MACHINE_IP` | Tente d'identifier le système d'exploitation.              |
| **Analyse approfondie**  | `sudo nmap -A MACHINE_IP` | Combine détection OS, versions des services et traceroute. |

***

### 🚀 Étape 3 : Utilisation des Scripts NSE

***

Nmap Scripting Engine (NSE) étend les fonctionnalités de Nmap avec des scripts prédéfinis.

#### Catégories de Scripts

| **Catégorie** | **Description**                                           |
| ------------- | --------------------------------------------------------- |
| `auth`        | Scripts pour tester des authentifications (ex. SSH, FTP). |
| `brute`       | Attaques par force brute.                                 |
| `vuln`        | Vérifie les vulnérabilités connues.                       |
| `exploit`     | Exploite les failles détectées.                           |
| `malware`     | Recherche de logiciels malveillants.                      |
| `safe`        | Scripts sûrs à exécuter, sans risques pour la cible.      |

***

#### Exemples de Scripts

**1. Découvrir des Vulnérabilités SMB**

```bash
nmap --script=smb-vuln-* -p 445 MACHINE_IP
```

> Vérifie les vulnérabilités SMB sur le port 445.

**2. Tester des Logins FTP avec Force Brute**

```bash
nmap --script=ftp-brute -p 21 MACHINE_IP
```

> Tente une attaque brute-force sur un serveur FTP.

**3. Récupérer des Informations HTTP**

```bash
nmap --script=http-* -p 80 MACHINE_IP
```

> Effectue diverses analyses HTTP (découverte de répertoires, tests SSL, etc.).

**4. Exécuter plusieurs catégories**

```bash
nmap --script="default or vuln" MACHINE_IP
```

> Lance les scripts par défaut et les scripts de détection de vulnérabilités.

***

### 🚀 Étape 4 : Options de Sortie

***

| **Option** | **Description**                                          |
| ---------- | -------------------------------------------------------- |
| `-oN file` | Sauvegarde les résultats au format texte classique.      |
| `-oG file` | Sauvegarde les résultats au format grepable.             |
| `-oX file` | Sauvegarde les résultats au format XML.                  |
| `-oA base` | Sauvegarde dans tous les formats (texte, XML, grepable). |

***

### 📋 Étape 5 : Scénarios Combinés

***

#### 1. Analyse Complète avec Scripts et Détection OS

```bash
sudo nmap -A --script=default,vuln -p- MACHINE_IP
```

* Combine les scripts par défaut et vulnérabilités, scanne tous les ports (`-p-`) et détecte l’OS (`-O`).

***

#### 2. Scan Masqué avec Fragmentation

```bash
sudo nmap -sS -f -p 22,80,443 MACHINE_IP
```

* Réalise un scan SYN avec fragmentation des paquets pour contourner les IDS.

***

#### 3. Analyse de Réseau avec Sauvegarde des Résultats

```bash
sudo nmap -sV -O -p 22,80,443 -oA scan_results 192.168.1.0/24
```

* Scanne un réseau entier, détecte les versions de services, OS et sauvegarde les résultats dans tous les formats.

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations légales** :
   * Scannez uniquement des réseaux où vous avez l’autorisation d’agir.
2. **Analysez les résultats avec d'autres outils** :
   * Exportez les résultats XML pour une utilisation dans **Metasploit** ou **OpenVAS**.
3. **Soyez discret** :
   * Si nécessaire, utilisez des scans masqués (`-f`, `-T2`), surtout dans des environnements sensibles.
4. **Commencez par des scans simples** :
   * Évitez de surcharger le réseau cible avec des scans trop agressifs au départ.
