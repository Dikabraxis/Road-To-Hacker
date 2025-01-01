# SNMP

### **SNMP - Guide Complet pour l'Énumération et le Pentest**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Le **SNMP (Simple Network Management Protocol)** est un protocole couramment utilisé pour la gestion et la surveillance des équipements réseau tels que routeurs, commutateurs, imprimantes, serveurs, etc. Si mal configuré, il peut exposer des informations sensibles ou permettre des modifications non autorisées.

***

### **1. Fonctionnement du Protocole SNMP**

**1.1 Ports et Versions**

* **Port 161 (UDP)** : Utilisé pour interroger les agents SNMP.
* **Port 162 (UDP)** : Utilisé pour les notifications SNMP (traps).
* **Versions :**
  * **SNMPv1** : Basique, non sécurisé (texte clair).
  * **SNMPv2c** : Fonctionnalités supplémentaires, mais toujours non sécurisé.
  * **SNMPv3** : Authentification et chiffrement, recommandé.

***

**1.2 Concepts Clés**

* **OID (Object Identifier)** : Identifie les paramètres ou ressources d'un dispositif.
* **MIB (Management Information Base)** : Structure hiérarchique définissant les OID.
* **Community Strings** :
  * **public** : Lecture seule (souvent vulnérable).
  * **private** : Accès en écriture.

***

### **2. Outils pour Énumérer SNMP**

Les outils suivants permettent d'explorer SNMP à différents niveaux :

**2.1 snmpwalk**

* Utilisé pour parcourir et extraire les informations disponibles via SNMP.
* Idéal pour une exploration détaillée d'un hôte.

**2.2 snmpget**

* Permet d’interroger des OID spécifiques pour récupérer des valeurs précises.

**2.3 onesixtyone**

* Optimisé pour tester rapidement des community strings sur un ou plusieurs hôtes.

**2.4 Braa**

* Conçu pour des scans massifs en parallèle sur plusieurs cibles SNMP.

**2.5 Nmap**

* Dispose de scripts puissants pour énumérer SNMP et détecter des configurations vulnérables.

***

### **3. Énumération de Base de SNMP**

**3.1 Scanner les Ports SNMP**

Identifiez les appareils avec le port SNMP ouvert :

```bash
nmap -p 161 -sU -sV <target>
```

**Explications :**

* `-p 161` : Cible le port SNMP.
* `-sU` : Scan UDP.
* `-sV` : Détecte la version du service.

***

**3.2 Tester les Community Strings**

**Avec onesixtyone**

Brute-force des community strings :

```bash
onesixtyone -c community_strings.txt <target>
```

**Explications :**

* `-c community_strings.txt` : Fichier contenant une liste de chaînes à tester.

**Résultat attendu :** Affiche les chaînes valides détectées.

***

**3.3 Interroger un Appareil**

**Avec snmpwalk**

Récupérez toutes les informations disponibles :

```bash
snmpwalk -v 2c -c public <target>
```

**Explications :**

* `-v 2c` : Utilise SNMP version 2c.
* `-c public` : Spécifie la community string (lecture seule).

**Avec snmpget**

Interrogez un OID précis :

```bash
snmpget -v 2c -c public <target> 1.3.6.1.2.1.1.1.0
```

**OID courants :**

* `1.3.6.1.2.1.1.1.0` : Description du système.
* `1.3.6.1.2.1.1.5.0` : Nom du système.

***

**3.4 Interroger plusieurs hôtes**

**Avec Braa**

Scannez plusieurs hôtes simultanément :

```bash
braa public@<target1>,<target2>,<target3>
```

**Explications :**

* Spécifie plusieurs cibles séparées par des virgules.
* Utilise la community string `public` par défaut.

**Exemple avec OID spécifique**

```bash
braa public@<target1>,<target2> sysDescr.0
```

**Résultat attendu :** Retourne la description des systèmes pour chaque cible.

***

**3.5 Scripts avec Nmap**

Automatisez les requêtes SNMP avec des scripts dédiés :

```bash
nmap -sU -p 161 --script=snmp-info <target>
```

**Scripts utiles :**

* `snmp-info` : Récupère des informations générales.
* `snmp-interfaces` : Liste les interfaces réseau.
* `snmp-brute` : Teste les community strings.

***

### **4. Énumération Avancée**

**4.1 Découvrir des Utilisateurs**

Utilisez snmpwalk pour énumérer les utilisateurs locaux :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.77.1.2.25
```

**4.2 Processus Actifs**

Identifiez les processus actifs :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2
```

**4.3 Configurations Réseau**

Récupérez les adresses IP configurées :

```bash
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.4.20.1.1
```

**4.4 Interrogation de Masses avec Braa**

Pour un grand nombre de cibles :

1. Préparez un fichier `targets.txt` contenant les adresses IP.
2.  Utilisez Braa avec ce fichier :

    ```bash
    braa public@ -f targets.txt sysName.0
    ```

***

### **5. Exploitation de SNMP**

**5.1 Modifier les Configurations**

Si la community string d'écriture (`private`) est trouvée, utilisez `snmpset` :

```bash
snmpset -v 2c -c private <target> <OID> i <value>
```

**Exemple :** Changer le nom du système :

```bash
snmpset -v 2c -c private <target> 1.3.6.1.2.1.1.5.0 s "NewDeviceName"
```

**5.2 Utilisation avec Metasploit**

1.  Lancez Metasploit :

    ```bash
    msfconsole
    ```
2.  Chargez le module SNMP :

    ```bash
    use auxiliary/scanner/snmp/snmp_enum
    set RHOSTS <target>
    set COMMUNITY public
    run
    ```

***

### **6. Sécurisation de SNMP**

1. **Désactiver les Versions Insecure** :
   * Remplacez SNMPv1 et SNMPv2c par SNMPv3.
2. **Changer les Community Strings** :
   * Évitez les valeurs par défaut (`public`, `private`).
   * Utilisez des chaînes complexes.
3. **Restreindre les Accès** :
   * Configurez des ACL pour limiter l'accès aux adresses IP de confiance.
4. **Désactiver SNMP si Inutilisé** :
   * Désactivez complètement SNMP sur les appareils non surveillés.
5. **Surveiller les Logs** :
   * Détectez les tentatives de scans ou d’accès non autorisés.

***

### **7. Comparaison des Outils SNMP**

| Outil           | Usage principal                            | Points forts                        |
| --------------- | ------------------------------------------ | ----------------------------------- |
| **snmpwalk**    | Exploration en profondeur d'un hôte        | Simplicité, informations détaillées |
| **snmpget**     | Récupération ciblée d'informations         | Précision                           |
| **onesixtyone** | Brute-force des community strings          | Rapidité                            |
| **Braa**        | Scans massifs en parallèle                 | Efficace sur des réseaux larges     |
| **Nmap**        | Énumération et détection de vulnérabilités | Polyvalence grâce aux scripts       |

***

### **8. Bonnes Pratiques**

* **Testez avec Autorisation** : Effectuez vos tests uniquement dans un cadre légal et éthique.
* **Corrélez les Données** : Combinez les informations SNMP avec d’autres sources (DNS, LDAP) pour une analyse complète.
* **Documentez Vos Résultats** : Notez les community strings, OID intéressants, et autres failles pour proposer des correctifs.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
