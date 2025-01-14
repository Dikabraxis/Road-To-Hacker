# xfreerdp / rdesktop

### Tutoriel : Utilisation de **xfreerdp** et **rdesktop** pour se connecter à un serveur RDP



⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

Ce guide vous montre comment utiliser les outils xfreerdp et rdesktop pour vous connecter à un serveur RDP, configurer un clavier français, partager des dossiers locaux, et activer des fonctionnalités comme le multi-écran et le presse-papiers.

***

### 1. Pré-requis

Assurez-vous que les outils sont installés sur votre système :

#### Installer xfreerdp :

```bash
sudo apt update
sudo apt install freerdp2-x11
```

#### Installer rdesktop (si vous souhaitez tester également) :

```bash
sudo apt install rdesktop
```

#### Ayez les informations nécessaires pour votre serveur RDP :

* Adresse IP ou nom du serveur.
* Nom d'utilisateur et mot de passe.

***

### 2. Commandes avec xfreerdp

#### Connexion basique

```bash
xfreerdp /u:<nom_utilisateur> /p:<mot_de_passe> /v:<adresse_ip_ou_nom_domaine>
```

**Exemple :**

```bash
xfreerdp /u:mon_utilisateur /p:mon_motdepasse /v:192.168.1.100
```

#### Configurer un clavier français

Ajoutez l'option `/kbd:0x0000040C` pour utiliser la disposition clavier français :

```bash
xfreerdp /u:<nom_utilisateur> /p:<mot_de_passe> /v:<adresse_ip_ou_nom_domaine> /kbd:0x0000040C
```

#### Partager un dossier local

Utilisez `/drive` pour partager un dossier local :

```bash
xfreerdp /u:<nom_utilisateur> /p:<mot_de_passe> /v:<adresse_ip_ou_nom_domaine> /drive:<nom_partage>,<chemin_local>
```

**Exemple :** Partager le dossier `/home/user/partage` en tant que "MesPartages" :

```bash
xfreerdp /u:mon_utilisateur /p:mon_motdepasse /v:192.168.1.100 /drive:MesPartages,/home/user/partage
```

#### Rediriger le presse-papiers

Ajoutez `/clipboard` pour copier-coller entre votre machine et le serveur :

```bash
xfreerdp /u:<nom_utilisateur> /p:<mot_de_passe> /v:<adresse_ip_ou_nom_domaine> /clipboard
```

#### Rediriger le son

Ajoutez `/sound` pour que le son du serveur soit redirigé vers votre machine :

```bash
xfreerdp /u:<nom_utilisateur> /p:<mot_de_passe> /v:<adresse_ip_ou_nom_domaine> /sound
```

#### Activer le multi-écran

Ajoutez `+multimon` pour utiliser plusieurs écrans lors de votre session RDP :

```bash
xfreerdp /u:<nom_utilisateur> /p:<mot_de_passe> /v:<adresse_ip_ou_nom_domaine> +multimon
```

#### Sélectionner des moniteurs spécifiques

Listez les moniteurs disponibles avec `/monitor-list` :

```bash
xfreerdp /monitor-list
```

Puis, spécifiez les moniteurs souhaités avec `/monitors` :

```bash
xfreerdp /u:<nom_utilisateur> /p:<mot_de_passe> /v:<adresse_ip_ou_nom_domaine> +multimon /monitors:0,1
```

#### Commande complète (avec clavier, multi-écran, dossier, presse-papiers et son)

Voici une commande combinée pour inclure toutes les options :

```bash
xfreerdp /u:mon_utilisateur /p:mon_motdepasse /v:192.168.1.100 /kbd:0x0000040C /drive:MesPartages,/home/user/partage /clipboard /sound +multimon /monitors:0,1
```

***

### 3. Commandes avec rdesktop

#### Connexion basique

```bash
rdesktop <adresse_ip_ou_nom_domaine> -u <nom_utilisateur> -p <mot_de_passe>
```

**Exemple :**

```bash
rdesktop 192.168.1.100 -u mon_utilisateur -p mon_motdepasse
```

#### Configurer un clavier français

Ajoutez l'option `-k fr` :

```bash
rdesktop <adresse_ip_ou_nom_domaine> -u <nom_utilisateur> -p <mot_de_passe> -k fr
```

#### Partager un dossier local

Ajoutez `-r disk` pour partager un dossier local :

```bash
rdesktop <adresse_ip_ou_nom_domaine> -u <nom_utilisateur> -p <mot_de_passe> -r disk:<nom_partage>=<chemin_local>
```

**Exemple :** Partager le dossier `/home/user/partage` en tant que "MesPartages" :

```bash
rdesktop 192.168.1.100 -u mon_utilisateur -p mon_motdepasse -r disk:MesPartages=/home/user/partage
```

#### Rediriger le presse-papiers

Ajoutez l'option `-r clipboard:PRIMARYCLIPBOARD` :

```bash
rdesktop <adresse_ip_ou_nom_domaine> -u <nom_utilisateur> -p <mot_de_passe> -r clipboard:PRIMARYCLIPBOARD
```

#### Rediriger le son

Ajoutez `-r sound:local` pour rediriger le son vers votre machine locale :

```bash
rdesktop <adresse_ip_ou_nom_domaine> -u <nom_utilisateur> -p <mot_de_passe> -r sound:local
```

#### Commande complète (avec clavier, dossier, presse-papiers et son)

Voici une commande combinée pour inclure toutes les options :

```bash
rdesktop 192.168.1.100 -u mon_utilisateur -p mon_motdepasse -k fr -r disk:MesPartages=/home/user/partage -r clipboard:PRIMARYCLIPBOARD -r sound:local
```

***

### 4. Différences entre xfreerdp et rdesktop

* **xfreerdp** est plus moderne et prend en charge les nouvelles fonctionnalités RDP (comme le son, le presse-papiers ou les partages avancés).
* **rdesktop** est plus léger, mais moins riche en fonctionnalités.

**Si possible, préférez xfreerdp**, car rdesktop n'est plus activement maintenu.

***

### 5. Dépannage

* **Erreur de clavier** : Vérifiez que la disposition est bien spécifiée avec `/kbd` (xfreerdp) ou `-k` (rdesktop).
* **Problème de connexion** : Assurez-vous que le port RDP (3389 par défaut) est ouvert sur le serveur.
* **Partage de dossiers inaccessible** : Vérifiez que vous avez les permissions nécessaires sur le dossier partagé et que le serveur RDP autorise les partages.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
