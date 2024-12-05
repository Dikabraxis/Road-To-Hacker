# Snmpwalk

### **snmpwalk - Guide Complet pour Interroger les Dispositifs SNMP**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**snmpwalk** est un outil en ligne de commande utilisé pour interroger les agents SNMP (Simple Network Management Protocol) sur des dispositifs réseau. Il permet de récupérer de manière itérative toutes les informations disponibles sous un OID (Object Identifier) spécifique. Cet outil est particulièrement utile pour la découverte, la surveillance, et l’audit de dispositifs connectés au réseau.

**Principales fonctionnalités :**

* Récupération d’informations détaillées sur un dispositif.
* Parcours des OID dans la MIB (Management Information Base).
* Utilisation sur les versions SNMPv1, SNMPv2c, et SNMPv3.

***

### **🚀 Étape 1 : Installation de snmpwalk**

**1. Installation sur Linux (Debian/Ubuntu)**

1.  Mettez à jour vos paquets :

    ```bash
    sudo apt update
    ```
2.  Installez les outils SNMP :

    ```bash
    sudo apt install snmp
    ```
3.  Vérifiez l’installation :

    ```bash
    snmpwalk --version
    ```

***

**2. Installation sur macOS**

1.  Installez **Homebrew** (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  Installez SNMP via Homebrew :

    ```bash
    brew install net-snmp
    ```
3.  Vérifiez l’installation :

    ```bash
    snmpwalk --version
    ```

***

**3. Installation sur Windows**

1. Téléchargez et installez **Net-SNMP** depuis Net-SNMP.
2. Ajoutez le chemin du répertoire d’installation au `PATH` système.
3.  Vérifiez l’installation :

    ```bash
    snmpwalk --version
    ```

***

### **🛠️ Étape 2 : Utilisation de Base de snmpwalk**

**1. Récupérer les Informations Systèmes**

Commande :

```bash
snmpwalk -v 2c -c public <target>
```

**Explications :**

* `-v 2c` : Utilise SNMP version 2c.
* `-c public` : Spécifie la community string (lecture seule, par défaut souvent `public`).
* `<target>` : Adresse IP ou nom d’hôte du dispositif.

**Exemple :**

```bash
snmpwalk -v 2c -c public 192.168.1.1
```

***

**2. Récupérer un OID Spécifique**

Commande :

```bash
snmpwalk -v 2c -c public <target> <OID>
```

**Explications :**

* `<OID>` : Identifie une branche spécifique de la MIB.

OID courants :

* `1.3.6.1.2.1.1.1.0` : Description du système.
* `1.3.6.1.2.1.1.5.0` : Nom du système.

**Exemple :**

```bash
snmpwalk -v 2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0
```

***

**3. Utiliser SNMPv3 pour des Connexions Sécurisées**

Commande :

```bash
snmpwalk -v 3 -u <username> -l authPriv -a <auth_protocol> -A <auth_password> -x <privacy_protocol> -X <privacy_password> <target>
```

**Explications :**

* `-u <username>` : Nom d’utilisateur SNMPv3.
* `-l authPriv` : Niveau de sécurité (authentification + chiffrement).
* `-a` et `-A` : Protocole et mot de passe d’authentification.
* `-x` et `-X` : Protocole et mot de passe de chiffrement.

**Exemple :**

```bash
snmpwalk -v 3 -u admin -l authPriv -a MD5 -A myAuthPassword -x DES -X myPrivPassword 192.168.1.1
```

***

**4. Filtrer les Résultats**

Pour limiter les résultats à un mot-clé spécifique :

```bash
bashCopier le codesnmpwalk -v 2c -c public <target> | grep <mot_clé>
```

**Exemple :**

```bash
snmpwalk -v 2c -c public 192.168.1.1 | grep uptime
```

***

### **🔍 Étape 3 : Cas Pratiques avec snmpwalk**

**1. Liste des Interfaces Réseau**

Commande :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.2.2.1.2
```

**Explications :**

* Cet OID retourne les noms des interfaces réseau sur l’appareil.

***

**2. Récupérer les Adresses IP Configurées**

Commande :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.4.20.1.1
```

**Explications :**

* Cet OID retourne les adresses IP configurées.

***

**3. Énumération des Processus Actifs**

Commande :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2
```

**Explications :**

* Cet OID retourne la liste des processus actifs.

***

**4. Énumération des Utilisateurs**

Commande :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.77.1.2.25
```

**Explications :**

* Cet OID retourne les utilisateurs locaux sur l’appareil.

***

**5. Découverte des Informations sur le Système**

Commande :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.1
```

**Explications :**

* Cet OID retourne des informations générales sur le système (nom, uptime, description).

***

### **📋 Étape 4 : Options Avancées avec snmpwalk**

**1. Limiter la Récursion**

Utilisez l’option `-r` pour limiter la profondeur des résultats :

```bash
snmpwalk -v 2c -c public -r 2 <target>
```

***

**2. Activer des Sorties Détaillées**

Pour afficher les détails des requêtes SNMP :

```bash
snmpwalk -v 2c -c public -d <target>
```

***

**3. Enregistrer les Résultats**

Sauvegardez les résultats dans un fichier pour analyse ultérieure :

```bash
snmpwalk -v 2c -c public <target> > results.txt
```

***

**4. Tester avec des Community Strings Alternatives**

Si la chaîne par défaut `public` ne fonctionne pas, essayez avec d'autres valeurs :

```bash
snmpwalk -v 2c -c private <target>
```

***

#### **5. Sécurisation et Bonnes Pratiques**

1. **Désactiver SNMP si Inutile :**
   * Désactivez le service sur les appareils non surveillés.
2. **Utiliser SNMPv3 :**
   * Préférez cette version pour le chiffrement et l’authentification.
3. **Restreindre les Accès :**
   * Configurez des ACL (Access Control Lists) pour limiter l'accès à des IP de confiance.
4. **Changer les Community Strings :**
   * Remplacez les valeurs par défaut (`public` et `private`) par des chaînes complexes et uniques.

***

### 📖 **Bonnes Pratiques pour l'Énumération avec snmpwalk**

* **Travaillez avec Autorisation :** Assurez-vous d’avoir la permission de tester un appareil SNMP.
* **Limitez les Résultats :** Interrogez uniquement les OID pertinents pour éviter des sorties volumineuses.
* **Corrélez les Données :** Combinez les informations SNMP avec d'autres outils comme **Nmap** ou **Metasploit** pour une analyse complète.

***

### **Résumé des Commandes Clés**

| Commande                                           | Description                      |
| -------------------------------------------------- | -------------------------------- |
| `snmpwalk -v 2c -c public <target>`                | Liste tous les OID accessibles.  |
| `snmpwalk -v 2c -c public <target> <OID>`          | Récupère un OID spécifique.      |
| `snmpwalk -v 3 -u <username> ...`                  | Utilisation de SNMPv3 sécurisé.  |
| `snmpwalk -v 2c -c public <target> grep <mot_clé>` | Recherche d'informations ciblées |

Avec ce guide, **snmpwalk** devient un outil puissant pour la gestion et la sécurité des appareils réseau. Sa simplicité et sa flexibilité en font un incontournable pour les administrateurs réseau et les pentesters.
