# Braa

### **Braa - Guide Complet pour Scanner et Interroger les Appareils SNMP**

***

### **Introduction**

**Braa** est un outil puissant et spécialisé dans les scans massifs de serveurs SNMP. Il est conçu pour interroger simultanément plusieurs appareils via des requêtes SNMP, ce qui le rend particulièrement adapté à des scans à grande échelle. Contrairement à d'autres outils comme **snmpwalk**, qui se concentre sur une cible à la fois, **Braa** est optimisé pour l'exécution en parallèle.

**Principales fonctionnalités :**

* Interroger rapidement un grand nombre de dispositifs SNMP.
* Support des OID personnalisés pour des requêtes ciblées.
* Compatible avec SNMPv1 et SNMPv2c.

***

### **🚀 Étape 1 : Installation de Braa**

**1. Installation sur Linux (Debian/Ubuntu)**

1.  Mettez à jour vos paquets :

    ```bash
    sudo apt update
    ```
2.  Installez Braa :

    ```bash
    sudo apt install braa
    ```
3.  Vérifiez l’installation :

    ```bash
    braa -h
    ```

***

**2. Installation depuis les Sources**

1.  Clonez le dépôt officiel :

    ```bash
    git clone https://github.com/patryk4815/braa.git
    ```
2.  Compilez l'outil :

    ```bash
    cd braa
    make
    ```
3.  Exécutez Braa :

    ```bash
    ./braa -h
    ```

***

**3. Installation sur macOS**

1.  Installez **Homebrew** (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2. Installez Braa via un gestionnaire de paquets (si disponible) ou compilez-le à partir des sources.

***

**4. Installation sur Windows**

Braa n'est pas nativement disponible pour Windows. Vous pouvez :

* Utiliser une machine virtuelle ou **WSL** avec Linux.
* Suivre les étapes d'installation pour Linux.

***

### **🛠️ Étape 2 : Utilisation de Base de Braa**

**1. Scanner une Cible Unique**

Commande :

```bash
braa public@<target>
```

**Explications :**

* `public` : Community string SNMP utilisée pour interroger l’appareil.
* `<target>` : Adresse IP ou nom de domaine de l’hôte.

**Exemple :**

```bash
braa public@192.168.1.1
```

***

**2. Scanner Plusieurs Cibles**

Commande :

```bash
braa public@<target1>,<target2>,<target3>
```

**Explications :**

* Permet de scanner plusieurs adresses en une seule commande, séparées par des virgules.

**Exemple :**

```bash
braa public@192.168.1.1,192.168.1.2,192.168.1.3
```

***

**3. Charger une Liste de Cibles à Partir d’un Fichier**

Pour interroger un grand nombre d’appareils, utilisez un fichier contenant les cibles :

```bash
braa public@ -f targets.txt
```

**Explications :**

* `-f targets.txt` : Fichier contenant une liste d'adresses IP (une par ligne).

**Exemple de contenu de `targets.txt` :**

```
192.168.1.1
192.168.1.2
192.168.1.3
```

***

**4. Utiliser un OID Spécifique**

Commande :

```bash
braa public@<target1>,<target2> sysDescr.0
```

**Explications :**

* `sysDescr.0` : Interroge l’OID pour récupérer la description du système.

**Exemple :**

```bash
braa public@192.168.1.1 sysDescr.0
```

**Résultat attendu :**

```ruby
192.168.1.1 => Linux Router
192.168.1.2 => Cisco Switch
```

***

### **🔍 Étape 3 : Cas Pratiques avec Braa**

**1. Découverte des Appareils SNMP sur un Réseau**

1. Préparez un fichier contenant les adresses IP du réseau (`targets.txt`).
2.  Lancez la commande suivante :

    ```bash
    braa public@ -f targets.txt sysName.0
    ```

**Explications :**

* Cette commande récupère les noms des systèmes (OID `sysName.0`) pour toutes les cibles.

***

**2. Tester une Configuration Réseau**

Pour récupérer les interfaces réseau sur plusieurs appareils :

```bash
braa public@192.168.1.1,192.168.1.2 1.3.6.1.2.1.2.2.1.2
```

**Explications :**

* Cet OID retourne les noms des interfaces réseau.

***

**3. Découvrir des Adresses IP Configurées**

Commande :

```bash
braa public@ -f targets.txt 1.3.6.1.2.1.4.20.1.1
```

**Explications :**

* Cet OID interroge les adresses IP configurées sur les appareils.

***

**4. Enregistrer les Résultats dans un Fichier**

Commande :

```bash
braa public@ -f targets.txt sysDescr.0 > results.txt
```

**Explications :**

* Les résultats de la commande sont sauvegardés dans `results.txt`.

***

### **📋 Étape 4 : Options Avancées de Braa**

**1. Limiter les Requêtes Simultanées**

Pour éviter de surcharger le réseau, limitez le nombre de requêtes parallèles :

```bash
braa -t 5 public@192.168.1.1,192.168.1.2 sysDescr.0
```

**Explications :**

* `-t 5` : Limite à 5 requêtes simultanées.

***

**2. Ajouter des Détails de Débogage**

Pour afficher des informations supplémentaires pendant l’exécution :

```bash
braa -d public@<target>
```

**Explications :**

* `-d` : Active le mode débogage.

***

**3. Scanner une Plage IP**

Braa ne supporte pas directement les plages IP, mais vous pouvez générer une liste avec un outil comme `seq` :

```bash
seq 1 254 | sed 's/^/192.168.1./' > targets.txt
braa public@ -f targets.txt sysName.0
```

***

#### **5. Résultats Attendus**

**Exemple de Sortie**

Pour une requête `sysDescr.0` :

```ruby
192.168.1.1 => Linux Router 4.15.0
192.168.1.2 => Cisco Switch IOS 15.2
```

Pour une requête `1.3.6.1.2.1.4.20.1.1` :

```ruby
192.168.1.1 => 192.168.1.1
192.168.1.2 => 192.168.1.254
```

***

#### **6. Sécurisation Contre les Scans Braa**

1. **Changer les Community Strings :**
   * Remplacez les valeurs par défaut (`public`, `private`) par des chaînes fortes et uniques.
2. **Limiter les Adresses Autorisées :**
   * Configurez des ACL pour n’autoriser que des IP de confiance.
3. **Utiliser SNMPv3 :**
   * Préférez SNMPv3, qui offre des mécanismes de chiffrement et d’authentification.
4. **Désactiver SNMP si Inutile :**
   * Supprimez SNMP des appareils où il n'est pas nécessaire.

***

### **Résumé des Commandes Clés**

| Commande                                              | Description                                       |
| ----------------------------------------------------- | ------------------------------------------------- |
| `braa public@<target>`                                | Interroge un hôte unique.                         |
| `braa public@<target1>,<target2>`                     | Interroge plusieurs hôtes.                        |
| `braa public@ -f targets.txt`                         | Charge une liste de cibles à partir d’un fichier. |
| `braa public@<target> sysDescr.0`                     | Récupère la description du système.               |
| `braa -t 5 public@<target1>,<target2>`                | Limite le nombre de requêtes simultanées à 5.     |
| `braa public@ -f targets.txt sysName.0 > results.txt` | Sauvegarde les résultats dans un fichier.         |

***

Avec ce guide, **Braa** devient un outil puissant pour scanner et interroger efficacement des réseaux SNMP. Sa capacité à gérer des requêtes massives en parallèle le rend indispensable pour les pentests et l’administration réseau. Assurez-vous toujours d’avoir une autorisation légale avant de l’utiliser.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
