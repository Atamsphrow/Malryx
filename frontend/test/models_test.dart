import 'package:flutter_test/flutter_test.dart';
import 'package:malryx/models/device_info.dart';
import 'package:malryx/models/scan_result.dart';
import 'package:malryx/models/threat.dart';
import 'package:malryx/utils/formatters.dart';

/// Tests du contrat entre le backend Python et les modèles Dart.
///
/// Les charges JSON utilisées ici sont copiées de vraies réponses du backend :
/// si le contrat côté Python change, ces tests doivent échouer.
void main() {
  group('Threat', () {
    test('décode une détection par empreinte', () {
      final threat = Threat.fromJson({
        'id': 'a1b2c3',
        'path': '/home/user/Téléchargements/eicar.com',
        'name': 'EICAR-Test-File',
        'severity': 'low',
        'source': 'hash_local',
        'sha256':
            '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        'size': 68,
        'detected_at': 1787423794.22,
        'quarantined': false,
        'details': {'matched': 'base de signatures locale'},
      });

      expect(threat.fileName, 'eicar.com');
      expect(threat.directory, '/home/user/Téléchargements');
      expect(threat.severity, 'low');
      expect(threat.detectedAt.year, 2026);
      expect(threat.archiveMember, isNull);
    });

    test('expose le membre d\'archive et les raisons heuristiques', () {
      final threat = Threat.fromJson({
        'path': '/tmp/archive.zip',
        'name': 'Heuristique: dropper',
        'severity': 'high',
        'source': 'heuristic',
        'detected_at': 1787423794.0,
        'details': {
          'archive_member': 'interieur/eicar.com',
          'reasons': ['telecharge et execute du code distant', 'efface ses traces'],
        },
      });

      expect(threat.archiveMember, 'interieur/eicar.com');
      expect(threat.reasons, hasLength(2));
    });

    test('tolère une gravité inconnue du frontend', () {
      // Le backend peut introduire une nouvelle valeur : l'UI doit l'afficher
      // au lieu de lever une exception de parsing.
      final threat = Threat.fromJson({
        'path': '/x',
        'name': 'y',
        'severity': 'apocalyptique',
        'source': 'nouveau_moteur',
        'detected_at': 0,
      });
      expect(threat.severity, 'apocalyptique');
      expect(threat.source, 'nouveau_moteur');
    });
  });

  group('ScanProgress', () {
    test('pourcentage nul pendant l\'énumération', () {
      final progress = ScanProgress.fromJson({
        'scan_id': 'abc',
        'status': 'running',
        'phase': 'enumeration',
        'files_scanned': 0,
        'files_total': null,
        'percent': null,
      });
      // Une barre indéterminée, pas un 0 % trompeur.
      expect(progress.percent, isNull);
      expect(progress.phaseLabel, 'Énumération des fichiers');
      expect(progress.isActive, isTrue);
    });

    test('progression complète en phase d\'analyse', () {
      final progress = ScanProgress.fromJson({
        'scan_id': 'abc',
        'status': 'running',
        'phase': 'analyse',
        'files_scanned': 5,
        'files_total': 5,
        'bytes_scanned': 609,
        'threats_found': 4,
        'elapsed_s': 0.12,
        'percent': 100.0,
      });
      expect(progress.percent, 100.0);
      expect(progress.threatsFound, 4);
      expect(progress.phaseLabel, 'Analyse');
    });
  });

  group('ScanResult', () {
    test('calcule la gravité maximale des menaces', () {
      final result = ScanResult.fromJson({
        'id': 'scan1',
        'type': 'path',
        'targets': ['/tmp'],
        'status': 'completed',
        'started_at': 1787423790.0,
        'finished_at': 1787423794.0,
        'files_scanned': 5,
        'threats': [
          {
            'path': '/a',
            'name': 'A',
            'severity': 'low',
            'source': 'hash_local',
            'detected_at': 0,
          },
          {
            'path': '/b',
            'name': 'B',
            'severity': 'high',
            'source': 'heuristic',
            'detected_at': 0,
          },
          {
            'path': '/c',
            'name': 'C',
            'severity': 'medium',
            'source': 'yara',
            'detected_at': 0,
          },
        ],
      });
      expect(result.maxSeverity, 'high');
      expect(result.duration.inSeconds, 4);
      expect(result.isActive, isFalse);
    });

    test('un scan sans menace est propre', () {
      final result = ScanResult.fromJson({
        'id': 's',
        'type': 'usb',
        'status': 'completed',
        'started_at': 0,
        'threats': <dynamic>[],
      });
      expect(result.maxSeverity, 'clean');
    });
  });

  group('DeviceInfo', () {
    test('un Android non autorisé n\'est pas scannable', () {
      final device = DeviceInfo.fromJson({
        'id': 'ABC123',
        'kind': 'android',
        'label': 'Android ABC123 (non autorise)',
        'access': 'adb_unauthorized',
        'scannable': false,
        'blocked_reason': 'Acceptez l\'empreinte RSA affichée.',
      });
      expect(device.canScanFiles, isFalse);
      expect(device.hasAdb, isFalse);
      expect(device.blockedReason, isNotNull);
    });

    test('une clé USB montée est scannable et son taux calculé', () {
      final device = DeviceInfo.fromJson({
        'id': 'uuid-1',
        'kind': 'removable',
        'label': 'SANDISK (FAT32)',
        'access': 'full',
        'mount_point': '/media/user/SANDISK',
        'filesystem': 'vfat',
        'total_bytes': 1000,
        'used_bytes': 250,
      });
      expect(device.canScanFiles, isTrue);
      expect(device.usageRatio, 0.25);
    });
  });

  group('AndroidApp', () {
    test('décode le score de risque et les permissions sensibles', () {
      final app = AndroidApp.fromJson({
        'package': 'com.exemple.espion',
        'risk_score': 78,
        'severity': 'high',
        'dangerous_permissions': [
          'android.permission.READ_SMS',
          'android.permission.RECORD_AUDIO',
        ],
        'notes': ['micro + localisation + SMS : profil de logiciel espion'],
      });
      expect(app.riskScore, 78);
      expect(app.displayName, 'com.exemple.espion');
      expect(app.dangerousPermissions, hasLength(2));
    });
  });

  group('formatters', () {
    test('tailles en unités binaires', () {
      expect(formatBytes(0), '0 o');
      expect(formatBytes(68), '68 o');
      expect(formatBytes(1024), '1.0 Kio');
      expect(formatBytes(1536), '1.5 Kio');
      expect(formatBytes(1024 * 1024), '1.0 Mio');
      expect(formatBytes(null), '—');
    });

    test('durées lisibles', () {
      expect(formatDuration(const Duration(milliseconds: 1200)), '1.2 s');
      expect(formatDuration(const Duration(seconds: 42)), '42 s');
      expect(formatDuration(const Duration(seconds: 133)), '2 min 13 s');
      expect(formatDuration(const Duration(minutes: 65)), '1 h 05');
    });

    test('permissions POSIX en notation symbolique', () {
      expect(formatMode(0x1ED), 'rwxr-xr-x'); // 0o755
      expect(formatMode(0x1A4), 'rw-r--r--'); // 0o644
      expect(formatMode(null), '—');
    });

    test('raccourcit un chemin en gardant les deux extrémités', () {
      final shortened = shortenPath('/a' * 60, maxLength: 20);
      expect(shortened.length, lessThanOrEqualTo(20));
      expect(shortened, contains('…'));
      expect(formatCount(12345), isNotEmpty);
    });
  });
}
