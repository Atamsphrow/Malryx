/// Miroir Dart de `backend/core/models.py::Threat`.
///
/// Les énumérations du backend sont conservées comme `String` plutôt que
/// converties en `enum` Dart : si le backend ajoute une gravité ou un moteur,
/// l'interface l'affiche telle quelle au lieu de lever une exception de parsing.
library;

class Threat {
  const Threat({
    required this.id,
    required this.path,
    required this.name,
    required this.severity,
    required this.source,
    this.sha256,
    this.size,
    required this.detectedAt,
    this.quarantined = false,
    this.details = const {},
  });

  final String id;
  final String path;
  final String name;
  final String severity;
  final String source;
  final String? sha256;
  final int? size;
  final DateTime detectedAt;
  final bool quarantined;
  final Map<String, dynamic> details;

  /// Nom du fichier seul, pour l'affichage compact en liste.
  String get fileName {
    final normalized = path.replaceAll('\\', '/');
    final index = normalized.lastIndexOf('/');
    return index == -1 ? normalized : normalized.substring(index + 1);
  }

  /// Dossier parent, affiché en second plan sous le nom du fichier.
  String get directory {
    final normalized = path.replaceAll('\\', '/');
    final index = normalized.lastIndexOf('/');
    return index <= 0 ? '/' : normalized.substring(0, index);
  }

  /// Chemin du membre concerné quand la menace vient d'une archive.
  String? get archiveMember => details['archive_member'] as String?;

  /// Explications de l'heuristique, listées telles quelles dans le détail.
  List<String> get reasons {
    final raw = details['reasons'];
    if (raw is List) return raw.map((e) => e.toString()).toList();
    return const [];
  }

  String? get virusTotalRatio => details['ratio'] as String?;

  factory Threat.fromJson(Map<String, dynamic> json) => Threat(
        id: json['id'] as String? ?? '',
        path: json['path'] as String? ?? '',
        name: json['name'] as String? ?? 'Menace inconnue',
        severity: json['severity'] as String? ?? 'medium',
        source: json['source'] as String? ?? 'heuristic',
        sha256: json['sha256'] as String?,
        size: (json['size'] as num?)?.toInt(),
        detectedAt: _epochToDate(json['detected_at']),
        quarantined: json['quarantined'] as bool? ?? false,
        details: (json['details'] as Map?)?.cast<String, dynamic>() ?? const {},
      );

  Threat copyWith({bool? quarantined}) => Threat(
        id: id,
        path: path,
        name: name,
        severity: severity,
        source: source,
        sha256: sha256,
        size: size,
        detectedAt: detectedAt,
        quarantined: quarantined ?? this.quarantined,
        details: details,
      );
}

/// Le backend transmet les horodatages en secondes Unix (float).
DateTime _epochToDate(dynamic value) {
  if (value is num) {
    return DateTime.fromMillisecondsSinceEpoch((value * 1000).round());
  }
  return DateTime.now();
}

/// Libellés des moteurs de détection, tels qu'affichés dans l'interface.
String detectionSourceLabel(String source) => switch (source) {
      'clamav' => 'ClamAV',
      'yara' => 'Règle YARA',
      'hash_local' => 'Empreinte connue',
      'virustotal' => 'VirusTotal',
      'heuristic' => 'Heuristique',
      'cve' => 'Vulnérabilité (CVE)',
      _ => source,
    };
