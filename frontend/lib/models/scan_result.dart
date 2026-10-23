// Miroir Dart de `backend/core/models.py` : résultats, progression, options.
// Toute modification du contrat côté Python doit être répercutée ici.

import 'threat.dart';

/// Types de scan reconnus par le backend. Les valeurs correspondent à
/// `ScanType` côté Python.
class ScanTypes {
  ScanTypes._();

  static const String path = 'path';
  static const String fullSystem = 'full_system';
  static const String memory = 'memory';
  static const String startup = 'startup';
  static const String packages = 'packages';
  static const String usb = 'usb';
  static const String android = 'android';
  static const String windows = 'windows';
  static const String linuxRemote = 'linux_remote';

  static String label(String type) => switch (type) {
        path => 'Dossier ou fichier',
        fullSystem => 'Système complet',
        memory => 'Mémoire et processus',
        startup => 'Points de démarrage',
        packages => 'Paquets installés',
        usb => 'Média amovible',
        android => 'Appareil Android',
        windows => 'Windows connecté',
        linuxRemote => 'Linux distant',
        _ => type,
      };
}

class ScanStatuses {
  ScanStatuses._();

  static const String pending = 'pending';
  static const String running = 'running';
  static const String completed = 'completed';
  static const String cancelled = 'cancelled';
  static const String failed = 'failed';

  static bool isActive(String status) =>
      status == pending || status == running;

  static String label(String status) => switch (status) {
        pending => 'En attente',
        running => 'En cours',
        completed => 'Terminé',
        cancelled => 'Annulé',
        failed => 'Échec',
        _ => status,
      };
}

/// Options envoyées avec une demande de scan.
class ScanOptions {
  const ScanOptions({
    this.useClamav = true,
    this.useYara = true,
    this.useHashDb = true,
    this.useVirustotal = false,
    this.useHeuristics = true,
    this.scanArchives = true,
    this.followSymlinks = false,
    this.autoQuarantine = false,
  });

  final bool useClamav;
  final bool useYara;
  final bool useHashDb;
  final bool useVirustotal;
  final bool useHeuristics;
  final bool scanArchives;
  final bool followSymlinks;
  final bool autoQuarantine;

  Map<String, dynamic> toJson() => {
        'use_clamav': useClamav,
        'use_yara': useYara,
        'use_hash_db': useHashDb,
        'use_virustotal': useVirustotal,
        'use_heuristics': useHeuristics,
        'scan_archives': scanArchives,
        'follow_symlinks': followSymlinks,
        'auto_quarantine': autoQuarantine,
      };

  ScanOptions copyWith({
    bool? useClamav,
    bool? useYara,
    bool? useHashDb,
    bool? useVirustotal,
    bool? useHeuristics,
    bool? scanArchives,
    bool? followSymlinks,
    bool? autoQuarantine,
  }) =>
      ScanOptions(
        useClamav: useClamav ?? this.useClamav,
        useYara: useYara ?? this.useYara,
        useHashDb: useHashDb ?? this.useHashDb,
        useVirustotal: useVirustotal ?? this.useVirustotal,
        useHeuristics: useHeuristics ?? this.useHeuristics,
        scanArchives: scanArchives ?? this.scanArchives,
        followSymlinks: followSymlinks ?? this.followSymlinks,
        autoQuarantine: autoQuarantine ?? this.autoQuarantine,
      );
}

/// Instantané de progression, reçu par WebSocket (`scan.progress`).
class ScanProgress {
  const ScanProgress({
    required this.scanId,
    required this.status,
    this.phase = '',
    this.currentFile,
    this.filesScanned = 0,
    this.filesTotal,
    this.bytesScanned = 0,
    this.threatsFound = 0,
    this.errors = 0,
    this.elapsedSeconds = 0,
    this.percent,
  });

  final String scanId;
  final String status;
  final String phase;
  final String? currentFile;
  final int filesScanned;
  final int? filesTotal;
  final int bytesScanned;
  final int threatsFound;
  final int errors;
  final double elapsedSeconds;

  /// `null` pendant l'énumération : le total n'est pas encore connu, l'UI doit
  /// alors afficher une barre indéterminée plutôt qu'un faux 0 %.
  final double? percent;

  bool get isActive => ScanStatuses.isActive(status);

  /// Libellé de phase affiché à l'utilisateur.
  String get phaseLabel => switch (phase) {
        'enumeration' => 'Énumération des fichiers',
        'analyse' => 'Analyse',
        'archives' => 'Analyse des archives',
        'termine' => 'Terminé',
        _ => phase.isEmpty ? 'Préparation' : phase,
      };

  factory ScanProgress.fromJson(Map<String, dynamic> json) => ScanProgress(
        scanId: json['scan_id'] as String? ?? '',
        status: json['status'] as String? ?? ScanStatuses.running,
        phase: json['phase'] as String? ?? '',
        currentFile: json['current_file'] as String?,
        filesScanned: (json['files_scanned'] as num?)?.toInt() ?? 0,
        filesTotal: (json['files_total'] as num?)?.toInt(),
        bytesScanned: (json['bytes_scanned'] as num?)?.toInt() ?? 0,
        threatsFound: (json['threats_found'] as num?)?.toInt() ?? 0,
        errors: (json['errors'] as num?)?.toInt() ?? 0,
        elapsedSeconds: (json['elapsed_s'] as num?)?.toDouble() ?? 0,
        percent: (json['percent'] as num?)?.toDouble(),
      );
}

/// Résultat complet d'un scan.
class ScanResult {
  const ScanResult({
    required this.id,
    required this.type,
    required this.targets,
    required this.status,
    this.deviceId,
    required this.startedAt,
    this.finishedAt,
    this.filesScanned = 0,
    this.filesSkipped = 0,
    this.bytesScanned = 0,
    this.errors = const [],
    this.threats = const [],
    this.enginesUsed = const [],
  });

  final String id;
  final String type;
  final List<String> targets;
  final String status;
  final String? deviceId;
  final DateTime startedAt;
  final DateTime? finishedAt;
  final int filesScanned;
  final int filesSkipped;
  final int bytesScanned;
  final List<String> errors;
  final List<Threat> threats;
  final List<String> enginesUsed;

  Duration get duration =>
      (finishedAt ?? DateTime.now()).difference(startedAt);

  bool get isActive => ScanStatuses.isActive(status);

  /// Gravité la plus élevée parmi les menaces trouvées.
  String get maxSeverity {
    const order = ['clean', 'low', 'medium', 'high', 'critical'];
    var worst = 'clean';
    for (final threat in threats) {
      if (order.indexOf(threat.severity) > order.indexOf(worst)) {
        worst = threat.severity;
      }
    }
    return worst;
  }

  factory ScanResult.fromJson(Map<String, dynamic> json) => ScanResult(
        id: json['id'] as String? ?? '',
        type: json['type'] as String? ?? ScanTypes.path,
        targets: (json['targets'] as List?)?.cast<String>() ?? const [],
        status: json['status'] as String? ?? ScanStatuses.pending,
        deviceId: json['device_id'] as String?,
        startedAt: _epochToDate(json['started_at']),
        finishedAt: json['finished_at'] == null
            ? null
            : _epochToDate(json['finished_at']),
        filesScanned: (json['files_scanned'] as num?)?.toInt() ?? 0,
        filesSkipped: (json['files_skipped'] as num?)?.toInt() ?? 0,
        bytesScanned: (json['bytes_scanned'] as num?)?.toInt() ?? 0,
        errors: (json['errors'] as List?)?.map((e) => e.toString()).toList() ??
            const [],
        threats: (json['threats'] as List?)
                ?.map((e) => Threat.fromJson((e as Map).cast<String, dynamic>()))
                .toList() ??
            const [],
        enginesUsed:
            (json['engines_used'] as List?)?.map((e) => e.toString()).toList() ??
                const [],
      );
}

/// Ligne d'historique : version allégée d'un scan, sans les menaces.
class ScanSummary {
  const ScanSummary({
    required this.id,
    required this.type,
    required this.targets,
    required this.status,
    required this.startedAt,
    this.durationSeconds = 0,
    this.filesScanned = 0,
    this.threatsCount = 0,
    this.maxSeverity = 'clean',
  });

  final String id;
  final String type;
  final List<String> targets;
  final String status;
  final DateTime startedAt;
  final double durationSeconds;
  final int filesScanned;
  final int threatsCount;
  final String maxSeverity;

  String get targetLabel =>
      targets.isEmpty ? ScanTypes.label(type) : targets.join(', ');

  factory ScanSummary.fromJson(Map<String, dynamic> json) => ScanSummary(
        id: json['id'] as String? ?? '',
        type: json['type'] as String? ?? ScanTypes.path,
        targets: (json['targets'] as List?)?.cast<String>() ?? const [],
        status: json['status'] as String? ?? ScanStatuses.completed,
        startedAt: _epochToDate(json['started_at']),
        durationSeconds: (json['duration_s'] as num?)?.toDouble() ?? 0,
        filesScanned: (json['files_scanned'] as num?)?.toInt() ?? 0,
        threatsCount: (json['threats_count'] as num?)?.toInt() ?? 0,
        maxSeverity: json['max_severity'] as String? ?? 'clean',
      );
}

/// État d'un moteur de détection, tel que rendu par /api/health.
class EngineStatus {
  const EngineStatus({
    required this.name,
    required this.available,
    this.version,
    this.signatures,
    this.detail,
  });

  final String name;
  final bool available;
  final String? version;
  final int? signatures;
  final String? detail;

  String get label => switch (name) {
        'clamav' => 'ClamAV',
        'yara' => 'YARA',
        'hash_local' => 'Empreintes locales',
        'virustotal' => 'VirusTotal',
        'heuristics' => 'Heuristiques',
        _ => name,
      };

  factory EngineStatus.fromJson(Map<String, dynamic> json) => EngineStatus(
        name: json['name'] as String? ?? '',
        available: json['available'] as bool? ?? false,
        version: json['version'] as String?,
        signatures: (json['signatures'] as num?)?.toInt(),
        detail: json['detail'] as String?,
      );
}

/// Réponse de /api/health.
class BackendHealth {
  const BackendHealth({
    required this.version,
    required this.platform,
    required this.isLinux,
    required this.root,
    this.engines = const [],
  });

  final String version;
  final String platform;
  final bool isLinux;
  final bool root;
  final List<EngineStatus> engines;

  factory BackendHealth.fromJson(Map<String, dynamic> json) => BackendHealth(
        version: json['version'] as String? ?? '?',
        platform: json['platform'] as String? ?? '?',
        isLinux: json['is_linux'] as bool? ?? false,
        root: json['root'] as bool? ?? false,
        engines: (json['engines'] as List?)
                ?.map((e) =>
                    EngineStatus.fromJson((e as Map).cast<String, dynamic>()))
                .toList() ??
            const [],
      );
}

/// Chiffres du tableau de bord (/api/stats).
class DashboardStats {
  const DashboardStats({
    this.scansCompleted = 0,
    this.filesScannedTotal = 0,
    this.lastScanAt,
    this.threatsTotal = 0,
    this.quarantineActive = 0,
    this.localSignatures = 0,
    this.activeScans = 0,
    this.realtimeProtection = false,
  });

  final int scansCompleted;
  final int filesScannedTotal;
  final DateTime? lastScanAt;
  final int threatsTotal;
  final int quarantineActive;
  final int localSignatures;
  final int activeScans;
  final bool realtimeProtection;

  factory DashboardStats.fromJson(Map<String, dynamic> json) => DashboardStats(
        scansCompleted: (json['scans_completed'] as num?)?.toInt() ?? 0,
        filesScannedTotal: (json['files_scanned_total'] as num?)?.toInt() ?? 0,
        lastScanAt: json['last_scan_at'] == null
            ? null
            : _epochToDate(json['last_scan_at']),
        threatsTotal: (json['threats_total'] as num?)?.toInt() ?? 0,
        quarantineActive: (json['quarantine_active'] as num?)?.toInt() ?? 0,
        localSignatures: (json['local_signatures'] as num?)?.toInt() ?? 0,
        activeScans: (json['active_scans'] as num?)?.toInt() ?? 0,
        realtimeProtection: json['realtime_protection'] as bool? ?? false,
      );
}

DateTime _epochToDate(dynamic value) {
  if (value is num) {
    return DateTime.fromMillisecondsSinceEpoch((value * 1000).round());
  }
  return DateTime.now();
}
