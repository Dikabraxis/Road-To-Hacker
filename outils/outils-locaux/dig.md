# Dig

## **DIG - Guide Complet pour Interroger les Serveurs DNS**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**



**DIG** (Domain Information Groper) est un outil puissant en ligne de commande pour interroger les serveurs DNS et analyser leur configuration. Utilisé par les administrateurs réseau, les pentesters, ou les développeurs, DIG permet de récupérer des informations précieuses sur les enregistrements DNS, comme les adresses IP, les enregistrements MX, ou les informations de zone.

**Principales fonctionnalités :**

* Résolution d’adresses IP à partir d’un nom de domaine (et vice versa).
* Requête des différents types d’enregistrements DNS (A, MX, TXT, etc.).
* Analyse de la configuration DNS d’un domaine.

***

### **🚀 Étape 1 : Installation de DIG**

**1. Installation sur Linux (Debian/Ubuntu)**

1.  Mettez à jour vos paquets :

    ```bash
    sudo apt update
    ```
2.  Installez le paquet `dnsutils` :

    ```bash
    sudo apt install dnsutils
    ```
3.  Vérifiez l’installation :

    ```bash
    dig -v
    ```

***

**2. Installation sur macOS**

DIG est inclus avec macOS via le package BIND. Si ce n’est pas le cas :

1.  Installez Homebrew (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  Installez BIND via Homebrew :

    ```bash
    brew install bind
    ```
3.  Vérifiez l’installation :

    ```bash
    dig -v
    ```

***

**3. Installation sur Windows**

1. Téléchargez et installez BIND depuis ISC.
2. Ajoutez le chemin d’installation au PATH système.
3.  Vérifiez l’installation :

    <pre class="language-bash"><code class="lang-bash"><strong>dig -v
    </strong></code></pre>

***

### **🛠️ Étape 2 : Utilisation de Base de DIG**

**1. Requête Simple pour une Adresse IP**

Commande :

```bash
dig example.com
```

**Explications :**

* Résout l’enregistrement A (par défaut) pour le domaine `example.com`.

***

**2. Spécifier un Type d’Enregistrement**

Commande :

```bash
dig example.com MX
```

**Explications :**

* Récupère l’enregistrement `MX` (serveur de messagerie) du domaine `example.com`.

Types courants :

* `A` : Adresse IPv4.
* `AAAA` : Adresse IPv6.
* `MX` : Serveur de messagerie.
* `NS` : Serveurs DNS autoritaires.
* `TXT` : Informations textuelles.
* `CNAME` : Alias de domaine.

***

**3. Interroger un Serveur DNS Spécifique**

Commande :

```bash
dig @8.8.8.8 example.com
```

**Explications :**

* Envoie une requête DNS au serveur `8.8.8.8` (Google Public DNS).

***

**4. Résolution Inverse**

Commande :

```bash
dig -x 93.184.216.34
```

**Explications :**

* Effectue une résolution inverse pour trouver le nom de domaine associé à l’IP `93.184.216.34`.

***

**5. Activer la Sortie Verbose**

Commande :

```bash
dig example.com +noall +answer
```

**Explications :**

* Affiche uniquement les réponses dans un format simplifié.

***

### **🔍 Étape 3 : Options Avancées et Scénarios Pratiques**

**1. Lister les Serveurs Autoritaires d’un Domaine**

Commande :

```bash
dig example.com NS
```

**Explications :**

* Récupère les serveurs DNS autoritaires pour `example.com`.

***

**2. Récupérer les Informations de Zone Complètes**

Commande :

```bash
dig @ns1.example.com example.com AXFR
```

**Explications :**

* Effectue un transfert de zone depuis `ns1.example.com` (si autorisé).

***

**3. Ajouter des Détails de Débogage**

Commande :

```bash
dig example.com +trace
```

**Explications :**

* Suivi complet de la résolution DNS, depuis les serveurs racines jusqu’aux serveurs autoritaires.

***

### **📋 Étape 4 : Exemples de Scénarios Pratiques**

**1. Vérification d’un Enregistrement SPF**

Commande :

```bash
dig example.com TXT
```

* Identifie les enregistrements SPF ou autres informations textuelles.

***

**2. Dépannage DNS**

1.  Résolution d’un domaine :

    ```bash
    dig example.com
    ```
2.  Vérification des serveurs DNS autoritaires :

    ```bash
    dig example.com NS
    ```
3.  Suivi de la résolution :

    ```bash
    dig example.com +trace
    ```

***

**3. Analyse de Performance**

Commande :

```bash
dig example.com +stats
```

* Affiche les statistiques, comme le temps de réponse.

***

### **📖 Bonnes Pratiques avec DIG**

* **Utilisez les bons types d’enregistrement :** Pour obtenir des réponses précises.
* **Associez avec d’autres outils :** Combinez DIG avec `nslookup` ou `host` pour un dépannage complet.
* **Testez plusieurs serveurs DNS :** Pour identifier les incohérences.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
