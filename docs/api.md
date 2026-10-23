# Contrat d'API Malryx

Base : `http://127.0.0.1:8765` — boucle locale uniquement. Le backend refuse de
démarrer sur une autre adresse.

Documentation interactive générée par FastAPI : `/docs`.

Les horodatages sont des secondes Unix (flottant). Les énumérations circulent
comme chaînes ; le frontend les conserve en `String` afin qu'une nouvelle valeur
côté backend s'affiche telle quelle au lieu de provoquer une erreur de parsing.

---

## Système

| Méthode | Chemin | Description |
|---|---|---|
| `GET` | `/api/health` | Version, plateforme, privilèges, état des moteurs |
| `GET` | `/api/stats` | Chiffres du tableau de bord |
| `GET` | `/api/settings` | Réglages persistants |
| `PUT` | `/api/settings` | Met à jour, persiste, recharge les moteurs |

`GET /api/health` :

```json
{
  "status": "ok",
  "version": "0.1.0",
  "platform": "linux",
  "is_linux": true,
  "root": false,
  "engines": [
    {"name": "hash_local", "available": true, "signatures": 1},
    {"name": "clamav", "available": true, "version": "ClamAV 1.0.3",
     "signatures": 27200, "detail": "daemon clamd (/run/clamav/clamd.ctl)"},
    {"name": "yara", "available": true, "signatures": 1},
    {"name": "heuristics", "available": true, "signatures": 9},
    {"name": "virustotal", "available": false, "detail": "aucune cle API configuree"}
  ]
}
```

Le champ `detail` contient la marche à suivre rédigée par le backend (« sudo apt
install clamav-daemon… »). L'interface l'affiche sans le reformuler.

`PUT /api/settings` accepte un objet partiel. La clé VirusTotal n'est jamais
renvoyée : la réponse expose `virustotal_key_set` (booléen) à sa place, et
envoyer une chaîne vide n'efface pas la clé stockée.

---

## Scans

| Méthode | Chemin | Description |
|---|---|---|
| `POST` | `/api/scans` | Lance un scan → `202` + descripteur |
| `GET` | `/api/scans` | Scans actifs + historique |
| `GET` | `/api/scans/{id}` | Résultat complet, menaces comprises |
| `GET` | `/api/scans/{id}/progress` | Progression instantanée |
| `POST` | `/api/scans/{id}/cancel` | Annule un scan en cours |
| `DELETE` | `/api/scans/{id}` | Retire un scan de l'historique |

### Lancer un scan

```http
POST /api/scans
{
  "type": "path",
  "targets": ["/home/user/Téléchargements"],
  "options": {
    "use_clamav": true, "use_yara": true, "use_hash_db": true,
    "use_heuristics": true, "use_virustotal": false,
    "scan_archives": true, "max_archive_depth": 3,
    "follow_symlinks": false, "auto_quarantine": false,
    "max_file_size": 268435456, "excluded_paths": []
  }
}
```

Réponse `202` immédiate : la progression arrive par WebSocket, pas dans la
réponse HTTP.

`type` : `path`, `full_system`, `startup`, `usb` (opérationnels) ·
`memory`, `packages` (non implémentés, le scan finit en `failed` avec le motif) ·
`android`, `windows`, `linux_remote` (passent par les routes dédiées).

Les options du scan sont **intersectées** avec les réglages globaux : un moteur
désactivé dans les réglages ne peut pas être réactivé par une requête.

Erreurs : `404` cible introuvable · `422` aucune cible fournie.

### Progression

`GET /api/scans/{id}/progress` — utile au démarrage de l'UI pour se raccrocher à
un scan déjà en cours, ou après une coupure du WebSocket.

```json
{
  "scan_id": "4cdb247f751c46a1",
  "status": "running",
  "phase": "analyse",
  "current_file": "/home/user/Téléchargements/gros.iso",
  "files_scanned": 1423,
  "files_total": 1890,
  "bytes_scanned": 8734129,
  "threats_found": 2,
  "errors": 0,
  "elapsed_s": 12.4,
  "percent": 75.3
}
```

`phase` : `enumeration` → `analyse` → `archives`.
`files_total` et `percent` valent `null` pendant l'énumération : le total n'est
pas encore connu. L'interface doit alors afficher une barre indéterminée.

Un scan terminé reste consultable 120 s en mémoire, puis la réponse est
reconstituée depuis la base (`phase: "termine"`).

---

## Appareils

| Méthode | Chemin | Description |
|---|---|---|
| `GET` | `/api/devices` | Inventaire complet |
| `GET` | `/api/devices/capabilities` | Outils système présents |
| `GET` | `/api/devices/autorun?mount_point=` | Fichiers d'exécution automatique |

`GET /api/devices` n'échoue jamais en bloc : si la détection Android tombe, les
clés USB sont quand même renvoyées.

```json
[
  {"id": "local", "kind": "local_host", "label": "Cette machine (debian)",
   "access": "full", "mount_point": "/"},
  {"id": "uuid-1234", "kind": "removable", "label": "SANDISK (FAT32)",
   "access": "full", "mount_point": "/media/user/SANDISK",
   "filesystem": "vfat", "total_bytes": 32000000000},
  {"id": "R58M12ABCDE", "kind": "android", "label": "samsung SM-A536B - Android 14",
   "access": "adb_debug", "details": {"rooted_hint": false}},
  {"id": "ABC123", "kind": "android", "label": "Android ABC123 (non autorise)",
   "access": "adb_unauthorized", "scannable": false,
   "blocked_reason": "Le debogage USB est actif mais cet ordinateur n'est pas autorise…"}
]
```

`access` : `full`, `adb_debug`, `adb_unauthorized`, `mtp_limited`, `smb`, `ssh`,
`none`. Quand `scannable` est `false`, `blocked_reason` explique quoi faire —
c'est un message destiné à l'utilisateur, à afficher tel quel.

Les identifiants d'appareils contiennent des `/` (`/dev/sda1`), ils passent donc
par des paramètres de requête, pas par le chemin de l'URL.

### Android

| Méthode | Chemin | Description |
|---|---|---|
| `GET` | `/api/devices/android/{serial}/apps` | Applications + permissions + score |
| `POST` | `/api/devices/android/{serial}/apps/{pkg}/uninstall` | Désinstalle |
| `POST` | `/api/devices/android/{serial}/apps/{pkg}/revoke` | Révoque une permission |

Paramètres : `include_system` (défaut `false`), `analyze` (défaut `true`, lit les
permissions via `dumpsys` — plus lent), `limit`.

Le tri est décroissant par `risk_score` (0-100). `notes` contient les
explications lisibles du score, à afficher directement.

`503` si `adb` est absent · `502` si la commande ADB échoue · `422` si le nom de
paquet est invalide.

### Windows et Linux distant

| Méthode | Chemin | Description |
|---|---|---|
| `GET` | `/api/devices/remote/windows/targets?mount_point=` | Sous-dossiers prioritaires |
| `POST` | `/api/devices/remote/smb/shares` | Énumère les partages SMB |
| `POST` | `/api/devices/remote/ssh/probe` | Teste l'accès SSH |
| `POST` | `/api/devices/remote/ssh/scan` | Empreintes distantes vs base locale |
| `POST` | `/api/devices/remote/ssh/packages` | Inventaire dpkg distant |

`POST /api/devices/remote/ssh/scan` fait calculer les SHA256 par la machine
distante (`find` + `sha256sum`, présents sur toute Debian) et les compare à la
base locale. Seules des empreintes traversent le réseau. ClamAV et YARA ne sont
pas applicables à distance sans agent, ce que la réponse précise dans `note`.

Le montage d'un partage SMB n'est jamais effectué par le backend : la réponse
fournit la commande `mount` à exécuter (`mount_hints`), c'est une décision de
l'utilisateur.

---

## Quarantaine

| Méthode | Chemin | Description |
|---|---|---|
| `GET` | `/api/quarantine` | Entrées actives (`include_inactive` pour l'historique) |
| `POST` | `/api/quarantine` | Isole un fichier |
| `POST` | `/api/quarantine/{id}/restore` | Restaure à l'emplacement d'origine |
| `DELETE` | `/api/quarantine/{id}` | Suppression définitive |
| `GET` | `/api/quarantine/orphans` | Fichiers sur disque absents de la base |

```http
POST /api/quarantine?force=false
{"path": "/tmp/suspect.sh", "threat_name": "Linux.ReverseShell.Bash", "severity": "high"}
```

- `409` — chemin système critique. Le corps explique pourquoi et la requête
  reste rejouable avec `force=true`. On utilise `409` et non `403` : la demande
  est comprise, c'est l'état de la cible qui la rend refusable.
- `400` — fichier introuvable, ou lien symbolique (il faut viser le fichier réel).
- `500` — erreur disque.

La restauration vérifie le SHA256 ; en cas d'écart elle est annulée et le
fichier restauré est retiré. Elle refuse aussi d'écraser un fichier existant.

---

## Signatures

| Méthode | Chemin | Description |
|---|---|---|
| `POST` | `/api/signatures/import` | Importe un fichier d'empreintes |
| `GET` | `/api/signatures/count` | Nombre d'empreintes en base |

Format, une entrée par ligne : `<sha256>:<nom>:<sévérité>`. Lignes vides et
commentaires `#` ignorés. Permet d'enrichir la détection sans reconstruire le
`.deb`.

---

## WebSocket

`ws://127.0.0.1:8765/ws` — tous les évènements.
`ws://127.0.0.1:8765/ws?scan_id=<id>` — filtré sur un scan.

Enveloppe commune :

```json
{"type": "scan.progress", "ts": 1787423794.22, "data": { }}
```

| Type | `data` |
|---|---|
| `hello` | `version`, `scan_id`, `active_scans` — envoyé à la connexion |
| `scan.started` | `scan_id`, `type`, `targets`, `engines` |
| `scan.progress` | identique à `GET /api/scans/{id}/progress` |
| `scan.threat` | `scan_id`, `threat` (objet complet) |
| `scan.finished` | `scan_id`, `status`, `summary`, `errors` |
| `scan.error` | `scan_id`, `message` |
| `device.connected` | `device_id`, `mount_point` |
| `device.disconnected` | `device_id` |
| `quarantine.changed` | `action` (`added`/`restored`/`deleted`), `id` |

### Garanties de livraison

Les évènements de **progression sont périssables** : si un client ne suit pas, la
plus ancienne progression est écrasée par la plus récente plutôt que de ralentir
le scan. La cadence est plafonnée à une publication toutes les 200 ms.

Les évènements de **cycle de vie** (`scan.threat`, `scan.finished`) ne sont
jamais écrasés.

Après une coupure, il n'y a **pas de rattrapage** : le client se reconnecte
(recul exponentiel plafonné à 10 s) puis resynchronise via
`GET /api/scans/{id}/progress`.

---

## Objet menace

```json
{
  "id": "3f2a1b",
  "path": "/home/user/Téléchargements/archive.zip",
  "name": "EICAR-Test-File",
  "severity": "low",
  "source": "hash_local",
  "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "size": 68,
  "detected_at": 1787423794.22,
  "quarantined": false,
  "details": {
    "archive_member": "interieur/eicar.com",
    "archive": "/home/user/Téléchargements/archive.zip"
  }
}
```

`severity` : `clean`, `low`, `medium`, `high`, `critical`.
`source` : `clamav`, `yara`, `hash_local`, `virustotal`, `heuristic`, `cve`.

`path` désigne toujours un chemin que l'utilisateur peut retrouver. Pour une
menace trouvée dans une archive, `path` est celui de l'archive et
`details.archive_member` le membre concerné — le dossier temporaire
d'extraction n'existe plus au moment de l'affichage.

`details` varie selon le moteur :

- **heuristic** — `score`, `reasons` (liste d'explications en français), `note`
- **yara** — `rule`, `tags`, `description`, `strings` (identifiants seuls,
  jamais les octets correspondants : un faux positif pourrait exposer des
  données sensibles)
- **virustotal** — `malicious`, `total_engines`, `ratio`, `permalink`
- **clamav** — `engine`
