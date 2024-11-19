# John The Ripper

#### Introduction

John the Ripper est un outil robuste de craquage de mots de passe conçu pour aider les administrateurs de systèmes, les auditeurs de sécurité, et les passionnés de cybersécurité à tester la robustesse des mots de passe dans leurs systèmes. Il supporte de nombreux formats de hachage et inclut des utilitaires qui facilitent la conversion de formats spécifiques de données cryptées (comme SSH, GPG) en un format que John peut traiter.

#### Installation de John the Ripper

**Sur Linux**

**Installer depuis les dépôts (pour les distributions basées sur Debian)**

```bash
sudo apt update
sudo apt install john
```

**Installer depuis les sources**

```bash
sudo apt install build-essential libssl-dev libgmp-dev
git clone https://github.com/openwall/john.git
cd john/src
./configure && make
sudo make install
```

#### Utilisation de Base

**Créer un Hash de Mots de Passe**

```bash
echo "password123" | john --stdin --format=raw-md5
```

**Explication :** Convertit le mot de passe en un hash MD5.&#x20;

**Craquage de Mots de Passe**

**Craquer des mots de passe à partir d'un fichier de hachages**

```bash
john --wordlist=<wordlist_file> <hash_file>
```

**Explication :** Utilise une liste de mots pour craquer les hachages.&#x20;

**Craquer des hachages en utilisant un mode de force brute**

```bash
john --incremental <hash_file>
```

**Explication :** Tente toutes les combinaisons possibles de mots de passe.&#x20;

#### Utilisation des Utilitaires `*2john`

John the Ripper comprend une série d'utilitaires nommés `*2john` qui sont utilisés pour extraire des hachages de divers types de fichiers cryptés. Ces utilitaires transforment les données cryptées en un format que John peut ensuite craquer.

**ssh2john**

**Utiliser ssh2john pour préparer les hachages de clés SSH**

```bash
ssh2john id_rsa > id_rsa.hash
```

**Explication :** Convertit une clé privée SSH en un format de hachage que John peut traiter.&#x20;

**gpg2john**

**Utiliser gpg2john pour extraire des hachages de fichiers GPG**

```bash
gpg2john private.key > private.key.hash
```

**Explication :** Prépare les hachages de clés GPG pour le craquage.&#x20;

#### Options Avancées et Discrétion

**Utiliser des Règles pour Améliorer les Attaques**

```bash
john --wordlist=<wordlist_file> --rules <hash_file>
```

**Explication :** Applique des modifications complexes aux mots de la liste pour craquer des hachages plus efficacement.

#### Exemples de Scénarios et Discrétion

**Craquage de Hachages MD5 avec une Liste de Mots**

```bash
john --wordlist=/path/to/wordlist.txt --format=raw-md5 hashes.txt
```

**Force Brute**

```bash
john --incremental --format=raw-md5 hashes.txt
```

#### Bonnes Pratiques

* **Obtenir des Autorisations :** Assurez-vous d'avoir l'autorisation nécessaire avant de tenter de craquer des mots de passe.
* **Limiter l'Impact :** Utilisez des techniques ciblées pour minimiser l'attention.
* **Surveiller les Ressources :** Soyez conscient de l'utilisation des ressources pour éviter de compromettre les performances du système.
