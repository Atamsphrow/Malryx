# Malryx

Antivirus local pour Debian, capable d'analyser la machine hôte **et** les
appareils qui lui sont connectés : téléphones Android, partitions Windows,
machines Linux distantes, médias amovibles.

- **Interface** : Flutter desktop (Linux), Material 3, mode sombre uniquement.
- **Moteur** : Python (FastAPI + WebSocket), utilisable seul en ligne de commande.
- **Identifiant applicatif** : `com.atamsphrow.malryx`

---

## État du projet

Cette première itération livre une **tranche verticale complète** : l'API, le
moteur de scan, les moteurs de détection et l'interface sont branchés de bout en
bout, avec un scan réellement fonctionnel.

### Vérifié en fonctionnement

| Fonction | État | Vérification |
|---|---|---|
| Scan d'un dossier / de fichiers | ✅ | 5 fichiers, 4 menaces détectées |
| Détection par empreinte SHA256 | ✅ | EICAR reconnu depuis la base locale |
| Heuristiques statiques | ✅ | dropper `curl \| bash`, double extension |
| Scan en profondeur des archives | ✅ | EICAR trouvé dans `archive.zip` |
| Progression temps réel (WebSocket) | ✅ | `scan.progress`, `scan.threat`, `scan.finished` |
| Quarantaine + restauration | ✅ | aller-retour bit-à-bit identique (MD5 vérifié) |
| Refus des chemins système critiques | ✅ | 10 cas, y compris `/bin/../etc/shadow` |
| Historique, statistiques, réglages | ✅ | REST complet |
| CLI autonome | ✅ | `health`, `scan`, `devices`, `quarantine`, `signatures` |
| Modèles Dart ↔ contrat Python | ✅ | 14 tests unitaires |

### Implémenté, non vérifiable hors Debian

Le code existe et suit les mêmes conventions, mais il n'a pas pu être exercé sur
cette machine de développement (Windows) :

- ClamAV via socket `clamd` (protocole INSTREAM) et repli `clamscan`
- Règles YARA (`yara-python` non installé ici)
- Détection des médias amovibles par `lsblk` / `/proc/mounts`
- Scan Android via ADB : appareils, applications, permissions, score de risque,
  désinstallation à distance
- Détection des partitions Windows montées, énumération des partages SMB
- Scan Linux distant par SSH (empreintes calculées à distance, inventaire dpkg)
- Scan des points de démarrage (cron, systemd, autostart, `ld.so.preload`)
- Auto-scan à l'insertion d'un média

### Pas encore implémenté

Ces points de la spec sont volontairement reportés à l'itération suivante. Le
backend renvoie une erreur explicite plutôt que de faire semblant :

- **Scan mémoire / processus** (`type: memory`) → `ScanStatus.failed` avec le
  motif
- **Paquets installés vs CVE** (`type: packages`) → idem ; l'inventaire dpkg
  distant fonctionne déjà, il manque le recoupement avec une base de
  vulnérabilités
- **Protection en temps réel** : le réglage existe et est persisté, mais aucune
  surveillance inotify n'est branchée. Le commutateur est grisé dans l'UI.
- **Agent léger Windows** (optionnel dans la spec §4.3)
- **Archives `.rar` / `.7z`** : demandent un outil externe ; `zip` et `tar`
  (avec gz/bz2/xz) sont gérés
- **Scan planifié** : le champ cron est stocké, aucun ordonnanceur ne le lit

---

## Contrainte de plateforme

Le projet **cible Debian** mais a été développé sous Windows. Conséquences :

- Le backend Python tourne et se teste sous Windows (garde-fous par plateforme
  explicites, jamais d'import conditionnel qui casserait le démarrage).
- **L'interface Flutter ne peut pas être compilée sur cette machine** : le build
  Linux exige Linux, et le build Windows exige la charge de travail « Desktop
  development with C++ » de Visual Studio, absente ici. L'UI est donc validée
  par l'analyse statique (`flutter analyze` : aucun problème) et 14 tests
  unitaires, pas par une exécution.
- Le `.deb` se construit uniquement sur Debian (ou dans un conteneur Debian).

---

## Architecture

```
malryx/
├── frontend/                    Application Flutter (Linux desktop)
│   ├── lib/
│   │   ├── main.dart            Coquille : rail de navigation + 5 écrans
│   │   ├── screens/             dashboard, scan, appareils, quarantaine, réglages
│   │   ├── services/
│   │   │   ├── api_client.dart        client REST
│   │   │   ├── websocket_client.dart  temps réel + reconnexion
│   │   │   └── backend_process.dart   lance le backend en sous-processus
│   │   ├── models/              miroir Dart du contrat Python
│   │   ├── state/app_state.dart  ChangeNotifier unique
│   │   ├── theme/app_theme.dart  Material You, sombre forcé
│   │   ├── widgets/             composants partagés
│   │   └── utils/formatters.dart formatage français
│   └── linux/                   configuration du build Linux
│
├── backend/                     Moteur Python
│   ├── main.py                  FastAPI + WebSocket + surveillance USB
│   ├── cli.py                   interface en ligne de commande
│   ├── api/                     scan_routes, device_routes, quarantine_routes
│   ├── core/
│   │   ├── models.py            contrat de données (Pydantic)
│   │   ├── scan_engine.py       orchestrateur : énumération, pipeline, archives
│   │   ├── quarantine.py        isolation réversible + garde-fous
│   │   ├── events.py            bus d'évènements thread → asyncio
│   │   ├── app_state.py         assemblage des composants
│   │   ├── config.py            chemins XDG, réglages persistants
│   │   └── platform_compat.py   exécution de commandes, garde Linux
│   ├── engines/                 base, clamav, yara, hash_checker, heuristics
│   ├── devices/                 usb, android, windows, linux_remote
│   ├── db/local_db.py           SQLite (historique, menaces, quarantaine, hash)
│   ├── rules/                   règles YARA livrées
│   └── signatures/              base d'empreintes livrée
│
└── packaging/                   .deb, PyInstaller, unité systemd
```

### Choix structurants

**Le backend n'écoute que sur `127.0.0.1`** et refuse de démarrer sur une autre
adresse. Un antivirus exposé au réseau serait une porte d'entrée, pas une
protection.

**Les scans vivent dans des threads**, l'API dans la boucle asyncio. Le seul
pont est `EventBus.publish_threadsafe`. Les évènements de progression sont
« périssables » : si un client sature, on écrase l'ancienne progression plutôt
que de ralentir le scan. Les menaces détectées, elles, ne sont jamais perdues.

**Le pourcentage est honnête.** Le scan compte d'abord les fichiers éligibles
(phase `enumeration`, sans stocker la liste — un scan système dépasse le million
d'entrées), puis analyse. Tant que le total est inconnu, l'API renvoie
`percent: null` et l'UI affiche une barre indéterminée au lieu d'un 0 %
trompeur.

**Les moteurs sont ordonnés du moins cher au plus cher** : empreintes locales,
ClamAV, YARA, heuristiques, puis VirusTotal. VirusTotal est sauté si un moteur
local a déjà tranché, ce qui économise le quota.

---

## Prérequis sur Debian

```bash
# Obligatoire
sudo apt install python3 python3-pip libgtk-3-0

# Fortement recommandé : moteur ClamAV
sudo apt install clamav-daemon clamav-freshclam
sudo freshclam
sudo systemctl enable --now clamav-daemon

# Selon les usages
sudo apt install android-tools-adb   # scan Android
sudo apt install util-linux          # lsblk, détection des médias
sudo apt install smbclient           # partages Windows
sudo apt install openssh-client      # Linux distant
```

Sans `clamd`, Malryx retombe sur le binaire `clamscan` : fonctionnel, mais
beaucoup plus lent (la base de signatures est rechargée à chaque fichier). Le
statut du moteur l'indique explicitement dans l'interface.

---

## Développement

### Backend

```bash
python -m pip install -r backend/requirements.txt

# Serveur (rechargement à chaud)
python backend/main.py --reload -v

# Documentation interactive de l'API
# → http://127.0.0.1:8765/docs
```

### Frontend

```bash
cd frontend
flutter pub get
flutter run -d linux
```

L'application démarre le backend elle-même si le port 8765 ne répond pas. En
développement, lancez-le à la main : l'app détectera qu'il tourne déjà et s'y
branchera plutôt que d'en lancer un second.

### Contrôles

```bash
python -m compileall -q backend    # syntaxe Python
cd frontend && flutter analyze     # analyse statique Dart
cd frontend && flutter test        # tests des modèles
```

---

## Ligne de commande

Le moteur est utilisable sans interface graphique — pratique en SSH sur une
machine sans session.

```bash
python backend/cli.py health                    # état des moteurs
python backend/cli.py scan ~/Téléchargements --archives
python backend/cli.py scan --type startup       # points de démarrage
python backend/cli.py scan --type full_system   # tout le système
python backend/cli.py devices                   # appareils détectés
python backend/cli.py quarantine list
python backend/cli.py quarantine add /chemin/suspect
python backend/cli.py quarantine restore <id>
python backend/cli.py signatures import ma-base.hashes
```

Code de sortie de `scan` : `0` si rien n'est trouvé, `1` si au moins une menace
l'est, `2` en cas d'erreur d'invocation. Utilisable dans un script.

Depuis le paquet installé : `malryx-scan <sous-commande>`.

---

## Construction du paquet

```bash
./packaging/build_deb.sh          # sur Debian uniquement
sudo apt install dist/malryx_0.1.0_amd64.deb
```

Le paquet embarque le bundle Flutter release et le backend compilé par
PyInstaller. Il n'exige donc **pas** de Python installé sur la machine cible.

Le choix de `.deb` plutôt que Flatpak ou Snap est délibéré : lire `/proc`,
parler à `adb`, monter des partitions et mettre en quarantaine des fichiers hors
du bac à sable est incompatible avec ces formats.

### Mise à jour des bases sans reconstruire le paquet

Les empreintes et les règles YARA sont lues depuis le dossier de données de
l'utilisateur, en plus de celles livrées :

```
~/.local/share/malryx/signatures/    empreintes ajoutées
~/.local/share/malryx/yara/          règles YARA ajoutées
```

Format des empreintes, une par ligne : `<sha256>:<nom>:<sévérité>`

---

## Sécurité et vie privée

**Aucune donnée ne quitte la machine par défaut.** VirusTotal est désactivé et
demande une activation explicite plus une clé API. Même activé, seules des
empreintes SHA256 sont transmises — jamais le contenu des fichiers. Le fait
d'envoyer une empreinte révèle tout de même à un tiers qu'un fichier précis
existe sur la machine : l'interface le dit clairement avant l'activation.

**La quarantaine est réversible.** Le fichier isolé est passé au XOR avec une
clé fixe et publique. Ce n'est pas du chiffrement et ce n'est pas présenté comme
tel : le but est qu'un fichier en quarantaine ne soit plus exécutable par
accident et ne soit plus redétecté en boucle. Le SHA256 d'origine est vérifié à
la restauration ; en cas d'écart, la restauration est annulée.

**Les chemins système vitaux sont refusés.** Un faux positif sur `/bin/bash` ou
`/usr/lib/libc.so.6` ne doit pas rendre la machine inamorçable. La mise en
quarantaine y est refusée (HTTP 409) sauf `force=true` explicite. La garde
normalise les chemins en POSIX, donc `/bin/../etc/shadow` est aussi refusé.

**Aucune commande n'est construite par concaténation.** `adb`, `ssh` et
`smbclient` sont appelés avec une liste d'arguments, sans shell. Les noms de
paquets, d'hôtes et de permissions sont validés par expression régulière avant
usage.

**Les bombes de décompression sont bornées** : 1 Gio extrait au maximum, 10 000
membres, ratio de compression 200:1, et la traversée de répertoire (`../`) est
bloquée à l'extraction.

**SSH conserve la vérification d'hôte.** `StrictHostKeyChecking` n'est pas
désactivé, et `BatchMode=yes` empêche toute demande de mot de passe qui
bloquerait le backend. L'authentification se fait par clé uniquement.

**La protection en temps réel n'est pas activée à l'installation.** L'unité
systemd est fournie mais laissée inactive : un antivirus qui se lance en daemon
sans qu'on le lui demande est une mauvaise surprise.

---

## Suite (§8 de la spec)

Les étapes 1 à 4 sont faites. Reste :

1. **Scan mémoire** : parcours de `/proc/*/exe`, détection des processus dont le
   binaire a été supprimé du disque (signal classique).
2. **CVE** : recoupement de l'inventaire dpkg avec une base de vulnérabilités
   (l'inventaire, local et distant, fonctionne déjà).
3. **Temps réel** : surveillance inotify des dossiers sensibles, branchée sur le
   pipeline de moteurs existant.
4. **Vérification sur Debian** de tout ce qui est marqué « non vérifiable hors
   Debian » ci-dessus, ClamAV et ADB en premier.
5. **Signature des APK** : `apksigner` pour remonter l'émetteur du certificat,
   champ déjà présent dans le modèle `AndroidApp`.
6. **Ordonnanceur** pour les scans planifiés.
