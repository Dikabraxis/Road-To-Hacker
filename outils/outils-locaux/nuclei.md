# Nuclei

## **Nuclei - Scanner de Vulnérabilités Basé sur des Templates**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**Nuclei** est un scanner de vulnérabilités rapide et personnalisable conçu pour les tests d'intrusion et l'audit de sécurité. Il fonctionne à l'aide de **templates YAML**, qui définissent des types spécifiques de tests. Nuclei permet d'identifier des failles dans des applications web, des services réseau, et plus encore.

#### **Fonctionnalités Principales :**

* **Vitesse et efficacité** : Scans optimisés pour une reconnaissance rapide.
* **Templates extensibles** : Utilisez ou créez vos propres templates pour des cas d'utilisation spécifiques.
* **Détection multivectorielle** : Compatible avec HTTP, DNS, TCP, UDP, etc.
* **Facilité d'intégration** : Intégré dans des workflows DevSecOps.

C'est un outil incontournable pour les professionnels en cybersécurité cherchant à automatiser l'audit des vulnérabilités.

***

### 🚀 **Installation de Nuclei**

#### **Sur Linux**

1.  Téléchargez la dernière version de Nuclei depuis GitHub :

    ```bash
    wget https://github.com/projectdiscovery/nuclei/releases/download/v2.9.0/nuclei_2.9.0_linux_amd64.zip
    ```
2.  Extrayez le fichier téléchargé :

    ```bash
    unzip nuclei_2.9.0_linux_amd64.zip
    ```
3.  Déplacez l'exécutable dans un dossier système (par exemple, `/usr/local/bin`) :

    ```bash
    sudo mv nuclei /usr/local/bin/
    ```
4.  Vérifiez l’installation :

    ```bash
    nuclei -version
    ```

***

#### **Sur macOS**

1.  Installez via Homebrew :

    ```bash
    brew install nuclei
    ```
2.  Vérifiez l’installation :

    ```bash
    nuclei -version
    ```

***

#### **Sur Windows**

1. Téléchargez l’exécutable depuis [GitHub](https://github.com/projectdiscovery/nuclei/releases).
2. Décompressez l'archive et placez l'exécutable dans un dossier accessible via le `PATH`.
3.  Ouvrez une invite de commande et testez avec :

    ```cmd
    nuclei -version
    ```

***

### **🛠️ Commandes de Base**

#### **1. Mise à Jour des Templates**

Avant de commencer à utiliser Nuclei, téléchargez les templates officiels :

```bash
nuclei -update-templates
```

Cette commande télécharge et met à jour les templates depuis le dépôt officiel.

***

#### **2. Scan Basique**

Pour exécuter un scan basique sur une URL cible :

```bash
nuclei -u https://example.com
```

***

#### **3. Utilisation de Templates Spécifiques**

Pour exécuter un template spécifique sur une URL :

```bash
nuclei -u https://example.com -t path/to/template.yaml
```

Exemple :

```bash
nuclei -u https://example.com -t cves/2021/CVE-2021-44228.yaml
```

***

#### **4. Scan d’un Fichier de Cibles**

Pour scanner une liste de cibles (par exemple, `targets.txt`) :

```bash
nuclei -l targets.txt
```

***

#### **5. Filtrage des Sévérités**

Pour exécuter uniquement les tests correspondant à une certaine sévérité :

```bash
nuclei -u https://example.com -severity critical,high
```

***

### **🔍 Options Avancées**

#### **1. Modes de Sortie**

Enregistrez les résultats dans différents formats :

1.  **Sortie standard :**

    ```bash
    nuclei -u https://example.com -o results.txt
    ```
2.  **JSON pour intégration dans d'autres outils :**

    ```bash
    nuclei -u https://example.com -o results.json -json
    ```

***

#### **2. Ajustement des Performances**

Pour ajuster les performances des scans :

1.  **Nombre de threads :** Augmentez le nombre de threads pour des scans plus rapides :

    ```bash
    nuclei -u https://example.com -c 50
    ```
2.  **Timeout des requêtes :** Ajustez le délai d'expiration des requêtes réseau :

    ```bash
    nuclei -u https://example.com -timeout 10
    ```

***

#### **3. Filtrage des Templates**

1.  **Par Tags :** Exécutez uniquement les templates associés à certains tags :

    ```bash
    nuclei -u https://example.com -tags cve,xss
    ```
2.  **Exclure des Templates :** Ignorez certains templates pendant le scan :

    ```bash
    nuclei -u https://example.com -exclude-tags dos
    ```

***

#### **4. Utilisation de Proxy**

Pour acheminer les requêtes via un proxy :

```bash
nuclei -u https://example.com -proxy http://127.0.0.1:8080
```

***

### **📋 Exemples de Scénarios d’Utilisation**

#### **1. Scan pour Vulnérabilités Connues**

Recherchez des CVE spécifiques sur une cible :

```bash
nuclei -u https://example.com -t cves/
```

***

#### **2. Identification des Mises en Œuvre Incorrectes**

Pour vérifier des configurations incorrectes ou des problèmes d’exposition :

```bash
nuclei -u https://example.com -t misconfiguration/
```

***

#### **3. Recherche de Failles Courantes**

Pour scanner des failles comme XSS, SQLi ou SSRF :

```bash
nuclei -u https://example.com -tags xss,sqli,ssrf
```

***

#### **4. Détection de Services**

Pour identifier les technologies utilisées sur une cible :

```bash
nuclei -u https://example.com -t technologies/
```

***

#### **5. Utilisation d’une Liste de Cibles**

Pour scanner un fichier contenant plusieurs URL :

```bash
nuclei -l urls.txt -t cves/
```

***

### **📚 Ressources Complémentaires**

1. **Dépôt Officiel de Nuclei :**
   * [Nuclei sur GitHub](https://github.com/projectdiscovery/nuclei)
2. **Templates Officiels :**
   * [Dépôt des Templates](https://github.com/projectdiscovery/nuclei-templates)
3. **Wordlists Utiles :**
   * [SecLists Wordlists](https://github.com/danielmiessler/SecLists)

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
