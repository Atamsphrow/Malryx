// Miroir Dart de `backend/core/models.py::QuarantineEntry`.
//
// Ce fichier ne figurait pas dans l'arborescence de la spec, mais la quarantaine
// (section 4.1) a son propre modèle côté backend : le représenter ici évite de
// manipuler des Map non typées dans l'écran de quarantaine.

class QuarantineStatuses {
  QuarantineStatuses._();

  static const String quarantined = 'quarantined';
  static const String restored = 'restored';
  static const String deleted = 'deleted';

  static String label(String status) => switch (status) {
        quarantined => 'En quarantaine',
        restored => 'Restauré',
        deleted => 'Supprimé',
        _ => status,
      };
}

class QuarantineEntry {
  const QuarantineEntry({
    required this.id,
    required this.originalPath,
    required this.storedPath,
    required this.sha256,
    required this.size,
    this.threatName,
    this.severity = 'medium',
    this.source,
    required this.quarantinedAt,
    this.status = QuarantineStatuses.quarantined,
    this.originalMode,
  });

  final String id;
  final String originalPath;
  final String storedPath;
  final String sha256;
  final int size;
  final String? threatName;
  final String severity;
  final String? source;
  final DateTime quarantinedAt;
  final String status;

  /// Permissions POSIX d'origine, restaurées avec le fichier.
  final int? originalMode;

  bool get isActive => status == QuarantineStatuses.quarantined;

  String get fileName {
    final normalized = originalPath.replaceAll('\\', '/');
    final index = normalized.lastIndexOf('/');
    return index == -1 ? normalized : normalized.substring(index + 1);
  }

  String get shortHash =>
      sha256.length > 16 ? '${sha256.substring(0, 16)}…' : sha256;

  factory QuarantineEntry.fromJson(Map<String, dynamic> json) =>
      QuarantineEntry(
        id: json['id'] as String? ?? '',
        originalPath: json['original_path'] as String? ?? '',
        storedPath: json['stored_path'] as String? ?? '',
        sha256: json['sha256'] as String? ?? '',
        size: (json['size'] as num?)?.toInt() ?? 0,
        threatName: json['threat_name'] as String?,
        severity: json['severity'] as String? ?? 'medium',
        source: json['source'] as String?,
        quarantinedAt: json['quarantined_at'] is num
            ? DateTime.fromMillisecondsSinceEpoch(
                ((json['quarantined_at'] as num) * 1000).round())
            : DateTime.now(),
        status: json['status'] as String? ?? QuarantineStatuses.quarantined,
        originalMode: (json['original_mode'] as num?)?.toInt(),
      );
}
