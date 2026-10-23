import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Lance et supervise le backend Python en sous-processus local.
///
/// Trois cas de figure, essayés dans cet ordre :
///
/// 1. **Un backend répond déjà** sur le port. C'est le cas en développement
///    quand on l'a lancé à la main (`python backend/main.py --reload`) : on ne
///    le remplace pas, on s'y branche.
/// 2. **Binaire embarqué** à côté de l'exécutable Flutter (`malryx-backend`,
///    produit par PyInstaller et installé par le paquet .deb).
/// 3. **Repli développement** : `python backend/main.py`, en remontant depuis
///    le dossier de build jusqu'à la racine du dépôt.
///
/// Le processus est tué à la fermeture de l'application pour ne pas laisser un
/// serveur orphelin qui garderait la base SQLite ouverte.
class BackendProcess {
  BackendProcess({this.port = 8765});

  final int port;

  Process? _process;
  bool _startedByUs = false;

  /// Dernières lignes de journal du backend, utiles pour diagnostiquer un
  /// démarrage raté sans aller chercher le fichier de log.
  final List<String> logTail = [];
  static const int _logTailMax = 100;

  bool get isManagedByUs => _startedByUs;

  /// Démarre le backend si nécessaire. Rend `true` si un processus a été lancé.
  Future<bool> ensureRunning() async {
    if (await _isPortAnswering()) return false;

    final executable = _findBundledBackend();
    if (executable != null) {
      await _spawn(executable.path, ['--port', '$port']);
      return true;
    }

    final devEntry = _findDevEntrypoint();
    if (devEntry != null) {
      await _spawn(_pythonCommand(), [devEntry.path, '--port', '$port']);
      return true;
    }

    throw StateError(
      'Backend Malryx introuvable. Attendu : "malryx-backend" à côté de '
      '${File(Platform.resolvedExecutable).parent.path}, ou backend/main.py '
      'dans le dépôt.',
    );
  }

  Future<void> _spawn(String executable, List<String> arguments) async {
    final process = await Process.start(
      executable,
      arguments,
      // Le backend ne doit pas hériter du terminal : ses sorties sont captées.
      mode: ProcessStartMode.normal,
    );
    _process = process;
    _startedByUs = true;

    void collect(Stream<List<int>> stream) {
      stream
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((line) {
        logTail.add(line);
        if (logTail.length > _logTailMax) logTail.removeAt(0);
      });
    }

    collect(process.stdout);
    collect(process.stderr);

    // Un backend qui meurt en cours de route doit laisser une trace claire.
    process.exitCode.then((code) {
      logTail.add('[backend] processus terminé avec le code $code');
      _process = null;
    });
  }

  /// Le port répond-il déjà ? Un simple TCP suffit, sans requête HTTP.
  Future<bool> _isPortAnswering() async {
    try {
      final socket = await Socket.connect(
        InternetAddress.loopbackIPv4,
        port,
        timeout: const Duration(milliseconds: 600),
      );
      socket.destroy();
      return true;
    } on SocketException {
      return false;
    }
  }

  /// Binaire PyInstaller installé par le paquet, à côté de l'exécutable.
  File? _findBundledBackend() {
    final dir = File(Platform.resolvedExecutable).parent;
    final name = Platform.isWindows ? 'malryx-backend.exe' : 'malryx-backend';
    for (final candidate in [
      File('${dir.path}${Platform.pathSeparator}$name'),
      // Disposition alternative : le binaire dans un sous-dossier lib/.
      File('${dir.path}${Platform.pathSeparator}lib'
          '${Platform.pathSeparator}$name'),
    ]) {
      if (candidate.existsSync()) return candidate;
    }
    return null;
  }

  /// backend/main.py, en remontant depuis le dossier de build.
  ///
  /// En développement l'exécutable se trouve dans
  /// `frontend/build/linux/x64/debug/bundle/`, la racine du dépôt est donc
  /// plusieurs niveaux au-dessus. On remonte jusqu'à la trouver.
  File? _findDevEntrypoint() {
    var dir = File(Platform.resolvedExecutable).parent;
    for (var depth = 0; depth < 10; depth++) {
      final candidate = File(
        '${dir.path}${Platform.pathSeparator}backend'
        '${Platform.pathSeparator}main.py',
      );
      if (candidate.existsSync()) return candidate;
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
    // Dernier recours : le répertoire courant (utile pour `flutter run`).
    final fromCwd = File(
      '${Directory.current.path}${Platform.pathSeparator}backend'
      '${Platform.pathSeparator}main.py',
    );
    if (fromCwd.existsSync()) return fromCwd;
    final fromParent = File(
      '${Directory.current.parent.path}${Platform.pathSeparator}backend'
      '${Platform.pathSeparator}main.py',
    );
    return fromParent.existsSync() ? fromParent : null;
  }

  String _pythonCommand() => Platform.isWindows ? 'python' : 'python3';

  /// Arrête le backend, seulement si c'est nous qui l'avons démarré.
  Future<void> stop() async {
    final process = _process;
    if (process == null || !_startedByUs) return;
    _process = null;
    // SIGTERM d'abord : uvicorn ferme proprement ses connexions et la base.
    process.kill(ProcessSignal.sigterm);
    try {
      await process.exitCode.timeout(const Duration(seconds: 5));
    } on TimeoutException {
      process.kill(ProcessSignal.sigkill);
    }
  }
}
