#!/usr/bin/env bash
#
# Construit le paquet .deb de Malryx.
#
# À exécuter SUR DEBIAN (ou dans un conteneur Debian) : la compilation du bundle
# Flutter Linux et de l'exécutable PyInstaller exige la plateforme cible. Ce
# script ne fonctionne pas depuis Windows ou macOS.
#
#   ./packaging/build_deb.sh              # construction complète
#   ./packaging/build_deb.sh --skip-flutter   # réutilise un bundle déjà compilé
#
# Disposition installée :
#   /usr/bin/malryx                      -> lanceur (script shell)
#   /usr/lib/malryx/malryx               -> exécutable Flutter
#   /usr/lib/malryx/malryx-backend       -> exécutable PyInstaller
#   /usr/lib/malryx/data/                -> assets Flutter
#   /usr/share/applications/             -> entrée de menu
#   /usr/share/icons/hicolor/            -> icône
#   /lib/systemd/system/                 -> unité temps réel (non activée)

set -euo pipefail

VERSION="0.1.0"
ARCH="amd64"
PACKAGE="malryx"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/deb"
STAGE="$BUILD/$PACKAGE-$VERSION"
DIST="$ROOT/dist"

SKIP_FLUTTER=0
for arg in "$@"; do
  case "$arg" in
    --skip-flutter) SKIP_FLUTTER=1 ;;
    *) echo "Option inconnue : $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mErreur :\033[0m %s\n' "$*" >&2; exit 1; }

# --- Vérifications ---------------------------------------------------------- #

[ "$(uname -s)" = "Linux" ] || die "ce script doit tourner sous Linux (cible Debian)."
command -v dpkg-deb >/dev/null || die "dpkg-deb absent : sudo apt install dpkg-dev"
command -v flutter  >/dev/null || die "flutter absent du PATH."
command -v pyinstaller >/dev/null || die "pyinstaller absent : pip install pyinstaller"

# --- 1. Backend : exécutable autonome --------------------------------------- #

log "Construction du backend avec PyInstaller"
cd "$ROOT"
pyinstaller packaging/malryx-backend.spec --clean --noconfirm \
  --distpath "$BUILD/pyinstaller" --workpath "$BUILD/pyi-work"

BACKEND_DIR="$BUILD/pyinstaller/malryx-backend"
[ -x "$BACKEND_DIR/malryx-backend" ] || die "l'exécutable du backend n'a pas été produit."

# --- 2. Frontend : bundle Flutter release ----------------------------------- #

if [ "$SKIP_FLUTTER" -eq 0 ]; then
  log "Construction du bundle Flutter (release, Linux)"
  cd "$ROOT/frontend"
  flutter config --enable-linux-desktop >/dev/null
  flutter pub get
  flutter build linux --release
  cd "$ROOT"
fi

FLUTTER_BUNDLE="$ROOT/frontend/build/linux/x64/release/bundle"
[ -d "$FLUTTER_BUNDLE" ] || die "bundle Flutter introuvable : $FLUTTER_BUNDLE"

# --- 3. Arborescence du paquet ---------------------------------------------- #

log "Assemblage de l'arborescence du paquet"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/bin" \
         "$STAGE/usr/lib/$PACKAGE" \
         "$STAGE/usr/share/applications" \
         "$STAGE/usr/share/icons/hicolor/256x256/apps" \
         "$STAGE/usr/share/doc/$PACKAGE" \
         "$STAGE/lib/systemd/system"

cp -r "$FLUTTER_BUNDLE"/. "$STAGE/usr/lib/$PACKAGE/"
# Le binaire PyInstaller et ses bibliothèques vont à côté de l'exécutable
# Flutter : c'est là que BackendProcess les cherche en premier.
cp -r "$BACKEND_DIR"/. "$STAGE/usr/lib/$PACKAGE/"

install -m 644 "$ROOT/packaging/debian/malryx.desktop" \
  "$STAGE/usr/share/applications/$PACKAGE.desktop"
install -m 644 "$ROOT/packaging/debian/malryx-realtime.service" \
  "$STAGE/lib/systemd/system/malryx-realtime.service"

if [ -f "$ROOT/packaging/icon-256.png" ]; then
  install -m 644 "$ROOT/packaging/icon-256.png" \
    "$STAGE/usr/share/icons/hicolor/256x256/apps/$PACKAGE.png"
else
  echo "Avertissement : packaging/icon-256.png absent, le paquet n'aura pas d'icône." >&2
fi

# Lanceur. Il place le répertoire courant dans /usr/lib/malryx pour que
# l'exécutable Flutter trouve ses assets, quelle que soit la façon dont il a
# été appelé.
cat > "$STAGE/usr/bin/$PACKAGE" <<'LAUNCHER'
#!/bin/sh
# Lanceur de Malryx.
cd /usr/lib/malryx || exit 1
exec ./malryx "$@"
LAUNCHER
chmod 755 "$STAGE/usr/bin/$PACKAGE"

# Lien vers la CLI du backend, pour l'usage en terminal ou par SSH.
cat > "$STAGE/usr/bin/$PACKAGE-scan" <<'CLI'
#!/bin/sh
# Interface en ligne de commande du moteur Malryx.
exec /usr/lib/malryx/malryx-backend --cli "$@"
CLI
chmod 755 "$STAGE/usr/bin/$PACKAGE-scan"

# --- 4. Métadonnées Debian -------------------------------------------------- #

INSTALLED_SIZE=$(du -sk "$STAGE" | cut -f1)
sed "s/^Installed-Size:.*/Installed-Size: $INSTALLED_SIZE/" \
  "$ROOT/packaging/debian/control" > "$STAGE/DEBIAN/control"

for script in postinst prerm postrm; do
  install -m 755 "$ROOT/packaging/debian/$script" "$STAGE/DEBIAN/$script"
done

# Les fichiers de configuration système ne doivent pas être écrasés à la mise
# à jour sans avertir l'utilisateur.
cat > "$STAGE/DEBIAN/conffiles" <<'CONF'
/lib/systemd/system/malryx-realtime.service
CONF

install -m 644 "$ROOT/README.md" "$STAGE/usr/share/doc/$PACKAGE/README.md" 2>/dev/null || true
gzip -9n "$STAGE/usr/share/doc/$PACKAGE/README.md" 2>/dev/null || true

# --- 5. Construction ------------------------------------------------------- #

log "Construction du .deb"
mkdir -p "$DIST"
DEB="$DIST/${PACKAGE}_${VERSION}_${ARCH}.deb"
# Les fichiers du paquet doivent appartenir à root, pas à l'utilisateur courant.
fakeroot dpkg-deb --build --root-owner-group "$STAGE" "$DEB" 2>/dev/null \
  || dpkg-deb --build --root-owner-group "$STAGE" "$DEB"

log "Vérification du paquet"
dpkg-deb --info "$DEB"
if command -v lintian >/dev/null 2>&1; then
  lintian --no-tag-display-limit "$DEB" || true
fi

log "Terminé : $DEB"
echo
echo "Installation :  sudo apt install $DEB"
echo "Désinstallation : sudo apt remove $PACKAGE"
