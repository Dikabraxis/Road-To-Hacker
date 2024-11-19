# Dirb

#### Introduction

DIRB est un outil de fuzzing web qui cherche des répertoires et fichiers web existants mais cachés ou non liés sur un serveur. Il fonctionne en lançant un dictionnaire de noms de fichiers et de répertoires contre un serveur web et en analysant les réponses. DIRB est très utile pour l'audit de sécurité pour découvrir des contenus cachés qui ne sont pas directement liés dans les pages visitées. Cela inclut des répertoires avec des permissions faibles, des fichiers de configuration laissés accessibles, et d'autres ressources qui pourraient être exploitées par un attaquant.

#### Installation de DIRB

**Sur Linux**

DIRB est souvent préinstallé dans des distributions orientées sécurité comme Kali Linux, mais il peut aussi être installé facilement sur n'importe quelle distribution basée sur Debian.

**Installer DIRB via apt**

```bash
sudo apt update
sudo apt install dirb
```

_Explication :_

* `sudo apt update` : Met à jour la liste des paquets disponibles.
* `sudo apt install dirb` : Installe DIRB.

**Sur Windows**

DIRB n'est pas disponible nativement pour Windows, mais il peut être utilisé via des environnements comme Cygwin ou Windows Subsystem for Linux (WSL).

**Utiliser WSL pour exécuter DIRB**

* Installez WSL via les fonctionnalités Windows, puis installez une distribution Linux comme Ubuntu.
* Une fois Ubuntu installé, ouvrez WSL et exécutez les commandes d'installation pour Linux mentionnées ci-dessus.

#### Utilisation de Base de DIRB et Discrétion

**Découverte de Répertoires et de Fichiers**

**Lancer un scan de base**

```bash
dirb http://example.com
```

_Explication :_ Lance un scan de base en utilisant les listes de mots par défaut fournies avec DIRB. _Discrétion :_ Moyenne à élevée. Cela peut générer beaucoup de trafic réseau et être facilement détecté par des systèmes IDS/IPS modernes.

**Test de Répertoires avec Wordlist Personnalisée**

**Utiliser une wordlist personnalisée**

```bash
dirb http://example.com /path/to/custom_wordlist
```

_Explication :_ Utilise une liste de mots personnalisée pour tester des chemins spécifiques sur le serveur cible. _Discrétion :_ Moyenne. Utiliser des listes de mots personnalisées peut réduire le trafic réseau, mais reste détectable par les journaux serveur.

#### Options Avancées et Discrétion

**Utiliser des Options de Ligne de Commande**

**Ignorer les réponses d'un certain type**

```bash
dirb http://example.com -N 404
```

_Explication :_ Ignore les réponses avec le code de statut 404, ce qui peut aider à réduire le bruit dans les résultats. _Discrétion :_ Moyenne. Cela réduit le nombre de requêtes fausses positives enregistrées par les systèmes de surveillance.

**Spécifier des extensions de fichiers**

```bash
dirb http://example.com -X .php,.html
```

_Explication :_ Teste uniquement les chemins avec les extensions spécifiées, ciblant ainsi les types de fichiers les plus susceptibles d'être vulnérables. _Discrétion :_ Moyenne à élevée. Cibler des extensions spécifiques peut accélérer le scan mais peut aussi attirer l'attention si les extensions visées sont sensibles.

#### Exemples de Scénarios et Discrétion

**Découverte de panneaux d'administration cachés**

```bash
dirb http://example.com /usr/share/dirb/wordlists/common.txt -X .php
```

_Explication :_ Cible les fichiers PHP souvent utilisés pour les interfaces d'administration. _Discrétion :_ Élevée. La recherche de panneaux d'administration peut être vue comme malveillante et attire souvent l'attention.

**Audit de sécurité d'une application web**

```bash
dirb http://example.com /path/to/security_audit_wordlist -N 200-299
```

_Explication :_ Concentre le scan sur les réponses avec des codes de succès (200-299), utile pour identifier les ressources exposées mais non sécurisées. _Discrétion :_ Moyenne. Limiter les codes de réponse peut réduire les logs indésirables.

#### Bonnes Pratiques

* **Obtenir des Autorisations :** Assurez-vous d'avoir l'autorisation nécessaire avant de lancer un scan avec DIRB pour éviter des implications légales.
* **Minimiser l'Impact :** Utilisez des tactiques comme les délais entre les requêtes (`-z`) pour minimiser l'impact sur le serveur cible.
* **Analyse Responsable :** Analysez les résultats avec soin et assurez-vous que toutes les découvertes sont traitées correctement pour sécuriser le système.
