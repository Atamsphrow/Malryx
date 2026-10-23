import 'dart:async';

import 'package:flutter/foundation.dart';

import '../models/device_info.dart';
import '../models/quarantine_entry.dart';
import '../models/scan_result.dart';
import '../models/threat.dart';
import '../services/api_client.dart';
import '../services/backend_process.dart';
import '../services/websocket_client.dart';

/// Étape du démarrage, affichée à l'utilisateur tant que l'application n'est
/// pas prête.
enum BackendPhase { starting, ready, failed }

/// Scan en cours de suivi par l'interface : progression et menaces au fil de
/// l'eau, alimentées par le WebSocket.
class ActiveScan {
  ActiveScan({required this.id, required this.type, required this.targets});

  final String id;
  final String type;
  final List<String> targets;

  ScanProgress? progress;
  final List<Threat> threats = [];
  String? errorMessage;
  bool finished = false;
  String status = ScanStatuses.pending;

  double? get percent => progress?.percent;
  bool get isActive => !finished;

  String get targetLabel =>
      targets.isEmpty ? ScanTypes.label(type) : targets.join(', ');
}

/// État partagé de l'application.
///
/// Un seul `ChangeNotifier` plutôt qu'un empilement de gestionnaires d'état :
/// l'application est un tableau de bord dont les écrans lisent tous les mêmes
/// données, et les mises à jour arrivent par une source unique (le WebSocket).
class AppState extends ChangeNotifier {
  AppState({ApiClient? api, BackendProcess? backend, int port = 8765})
      : _api = api ?? ApiClient(port: port),
        _backend = backend ?? BackendProcess(port: port),
        _port = port;

  final ApiClient _api;
  final BackendProcess _backend;
  final int _port;
  WebSocketClient? _ws;
  StreamSubscription<BackendEvent>? _wsSubscription;

  ApiClient get api => _api;

  // -- état du backend ---------------------------------------------------- //

  BackendPhase phase = BackendPhase.starting;
  String? startupError;
  BackendHealth? health;
  HostCapabilities capabilities = const HostCapabilities();

  bool get wsConnected => _ws?.isConnected ?? false;

  /// Vrai si l'on tourne hors Linux : certaines fonctions sont alors inertes,
  /// l'interface le signale au lieu de faire croire qu'elles marchent.
  bool get isDevelopmentPlatform => health != null && !health!.isLinux;

  // -- données ------------------------------------------------------------ //

  DashboardStats stats = const DashboardStats();
  List<DeviceInfo> devices = [];
  List<ScanSummary> history = [];
  List<QuarantineEntry> quarantine = [];
  Map<String, dynamic> settings = {};

  ActiveScan? activeScan;

  /// Dernier résultat consulté en détail (écran de résultats).
  ScanResult? selectedScan;

  /// Message transitoire à afficher dans un bandeau (erreur d'action, succès).
  String? notice;
  bool noticeIsError = false;

  // -- démarrage ---------------------------------------------------------- //

  Future<void> initialize() async {
    phase = BackendPhase.starting;
    startupError = null;
    notifyListeners();
    try {
      await _backend.ensureRunning();
      health = await _api.waitUntilReady();
      _connectWebSocket();
      await refreshAll();
      phase = BackendPhase.ready;
    } catch (error) {
      phase = BackendPhase.failed;
      startupError = _describe(error);
      if (_backend.logTail.isNotEmpty) {
        startupError =
            '$startupError\n\nJournal du backend :\n${_backend.logTail.takeLast(8).join('\n')}';
      }
    }
    notifyListeners();
  }

  void _connectWebSocket() {
    _ws?.dispose();
    final ws = WebSocketClient(
      port: _port,
      // Après une coupure, la progression manquée est perdue : on resynchronise
      // depuis l'API plutôt que d'espérer un rattrapage.
      onReconnected: _resyncAfterReconnect,
    );
    _ws = ws;
    _wsSubscription = ws.events.listen(_handleEvent);
    ws.connect();
  }

  Future<void> _resyncAfterReconnect() async {
    final scan = activeScan;
    if (scan != null && scan.isActive) {
      try {
        final progress = await _api.getProgress(scan.id);
        scan.progress = progress;
        scan.status = progress.status;
        if (!ScanStatuses.isActive(progress.status)) {
          await _finalizeScan(scan.id);
        }
      } catch (_) {
        // Le scan a peut-être disparu (backend redémarré) : on l'oublie.
      }
    }
    await refreshAll();
  }

  // -- évènements temps réel ---------------------------------------------- //

  void _handleEvent(BackendEvent event) {
    switch (event.type) {
      case EventTypes.scanProgress:
        final scan = activeScan;
        if (scan == null || scan.id != event.scanId) return;
        scan.progress = ScanProgress.fromJson(event.data);
        scan.status = scan.progress!.status;
        notifyListeners();

      case EventTypes.scanThreat:
        final scan = activeScan;
        if (scan == null || scan.id != event.scanId) return;
        final raw = event.data['threat'];
        if (raw is Map) {
          scan.threats.add(Threat.fromJson(raw.cast<String, dynamic>()));
          notifyListeners();
        }

      case EventTypes.scanFinished:
        final scanId = event.scanId;
        if (scanId == null) return;
        _finalizeScan(scanId, statusFromEvent: event.data['status'] as String?);

      case EventTypes.scanError:
        final scan = activeScan;
        if (scan != null && scan.id == event.scanId) {
          scan.errorMessage = event.data['message'] as String?;
          notifyListeners();
        }

      case EventTypes.deviceConnected:
      case EventTypes.deviceDisconnected:
        final mount = event.data['mount_point'];
        if (event.type == EventTypes.deviceConnected && mount is String) {
          _setNotice('Média détecté : $mount', isError: false);
        }
        refreshDevices();

      case EventTypes.quarantineChanged:
        refreshQuarantine();
    }
  }

  Future<void> _finalizeScan(String scanId, {String? statusFromEvent}) async {
    final scan = activeScan;
    if (scan == null || scan.id != scanId) {
      await refreshStats();
      await refreshHistory();
      return;
    }
    scan.finished = true;
    scan.status = statusFromEvent ?? ScanStatuses.completed;
    notifyListeners();
    // On recharge le résultat complet : il contient les menaces consolidées et
    // les erreurs, y compris celles arrivées avant l'ouverture du WebSocket.
    try {
      selectedScan = await _api.getScan(scanId);
    } catch (_) {
      // Résultat indisponible : la liste temps réel reste affichée.
    }
    await refreshStats();
    await refreshHistory();
    notifyListeners();
  }

  // -- rafraîchissements -------------------------------------------------- //

  Future<void> refreshAll() async {
    await Future.wait([
      refreshStats(),
      refreshDevices(),
      refreshHistory(),
      refreshQuarantine(),
      refreshSettings(),
      refreshCapabilities(),
    ]);
  }

  Future<void> refreshStats() async {
    try {
      stats = await _api.stats();
      notifyListeners();
    } catch (_) {/* transitoire, on garde la valeur précédente */}
  }

  Future<void> refreshDevices() async {
    try {
      devices = await _api.devices();
      notifyListeners();
    } catch (_) {}
  }

  Future<void> refreshHistory() async {
    try {
      final result = await _api.listScans(limit: 30);
      history = result.history;
      notifyListeners();
    } catch (_) {}
  }

  Future<void> refreshQuarantine() async {
    try {
      quarantine = await _api.quarantine();
      notifyListeners();
    } catch (_) {}
  }

  Future<void> refreshSettings() async {
    try {
      settings = await _api.settings();
      notifyListeners();
    } catch (_) {}
  }

  Future<void> refreshCapabilities() async {
    try {
      capabilities = await _api.capabilities();
      notifyListeners();
    } catch (_) {}
  }

  Future<void> refreshHealth() async {
    try {
      health = await _api.health();
      notifyListeners();
    } catch (_) {}
  }

  // -- actions ------------------------------------------------------------ //

  Future<bool> startScan({
    required String type,
    List<String> targets = const [],
    String? deviceId,
    ScanOptions options = const ScanOptions(),
  }) async {
    if (activeScan?.isActive ?? false) {
      _setNotice('Un scan est déjà en cours.', isError: true);
      return false;
    }
    try {
      final scan = await _api.startScan(
        type: type,
        targets: targets,
        deviceId: deviceId,
        options: options,
      );
      activeScan =
          ActiveScan(id: scan.id, type: scan.type, targets: scan.targets);
      selectedScan = null;
      notifyListeners();
      return true;
    } catch (error) {
      _setNotice(_describe(error), isError: true);
      return false;
    }
  }

  Future<void> cancelActiveScan() async {
    final scan = activeScan;
    if (scan == null || !scan.isActive) return;
    try {
      await _api.cancelScan(scan.id);
    } catch (error) {
      _setNotice(_describe(error), isError: true);
    }
  }

  /// Oublie le scan suivi pour revenir à l'écran de lancement.
  void clearActiveScan() {
    activeScan = null;
    notifyListeners();
  }

  /// Ferme la vue de résultat détaillé.
  void clearSelectedScan() {
    selectedScan = null;
    notifyListeners();
  }

  Future<void> openScan(String scanId) async {
    try {
      selectedScan = await _api.getScan(scanId);
      notifyListeners();
    } catch (error) {
      _setNotice(_describe(error), isError: true);
    }
  }

  /// Isole un fichier. `force` n'est proposé qu'après un premier refus.
  Future<bool> quarantineThreat(Threat threat, {bool force = false}) async {
    try {
      await _api.quarantineFile(
        threat.path,
        threatName: threat.name,
        severity: threat.severity,
        force: force,
      );
      _markThreatQuarantined(threat.id);
      await refreshQuarantine();
      _setNotice('${threat.fileName} placé en quarantaine.', isError: false);
      return true;
    } catch (error) {
      _setNotice(_describe(error), isError: true);
      return false;
    }
  }

  void _markThreatQuarantined(String threatId) {
    final scan = activeScan;
    if (scan != null) {
      final index = scan.threats.indexWhere((t) => t.id == threatId);
      if (index != -1) {
        scan.threats[index] = scan.threats[index].copyWith(quarantined: true);
      }
    }
    notifyListeners();
  }

  Future<void> restoreQuarantine(String id) async {
    try {
      final path = await _api.restoreQuarantine(id);
      await refreshQuarantine();
      _setNotice('Restauré : $path', isError: false);
    } catch (error) {
      _setNotice(_describe(error), isError: true);
    }
  }

  Future<void> deleteQuarantine(String id) async {
    try {
      await _api.deleteQuarantine(id);
      await refreshQuarantine();
      _setNotice('Fichier supprimé définitivement.', isError: false);
    } catch (error) {
      _setNotice(_describe(error), isError: true);
    }
  }

  Future<void> updateSetting(String key, Object? value) async {
    try {
      settings = await _api.updateSettings({key: value});
      await refreshHealth();
      notifyListeners();
    } catch (error) {
      _setNotice(_describe(error), isError: true);
    }
  }

  Future<List<AndroidApp>> androidApps(String serial,
      {bool includeSystem = false}) async {
    return _api.androidApps(serial, includeSystem: includeSystem);
  }

  Future<void> uninstallAndroidApp(String serial, String package) async {
    try {
      final output = await _api.uninstallAndroidApp(serial, package);
      _setNotice('$package : $output', isError: false);
    } catch (error) {
      _setNotice(_describe(error), isError: true);
    }
  }

  // -- messages ----------------------------------------------------------- //

  void _setNotice(String message, {required bool isError}) {
    notice = message;
    noticeIsError = isError;
    notifyListeners();
  }

  void clearNotice() {
    if (notice == null) return;
    notice = null;
    notifyListeners();
  }

  String _describe(Object error) {
    if (error is ApiException) return error.detail;
    if (error is BackendUnavailable) return error.toString();
    if (error is StateError) return error.message;
    return error.toString();
  }

  @override
  Future<void> dispose() async {
    await _wsSubscription?.cancel();
    await _ws?.dispose();
    _api.dispose();
    await _backend.stop();
    super.dispose();
  }
}

extension _TakeLast<T> on List<T> {
  Iterable<T> takeLast(int count) =>
      length <= count ? this : skip(length - count);
}
