// Miroir Dart de `backend/core/models.py` : appareils et applications Android.

import 'package:flutter/material.dart';

/// Familles d'appareils, correspond à `DeviceKind` côté Python.
class DeviceKinds {
  DeviceKinds._();

  static const String localHost = 'local_host';
  static const String removable = 'removable';
  static const String android = 'android';
  static const String windowsHost = 'windows_host';
  static const String linuxHost = 'linux_host';

  static String label(String kind) => switch (kind) {
        localHost => 'Cette machine',
        removable => 'Média amovible',
        android => 'Android',
        windowsHost => 'Windows',
        linuxHost => 'Linux distant',
        _ => kind,
      };

  static IconData icon(String kind) => switch (kind) {
        localHost => Icons.computer_outlined,
        removable => Icons.usb_outlined,
        android => Icons.smartphone_outlined,
        windowsHost => Icons.desktop_windows_outlined,
        linuxHost => Icons.dns_outlined,
        _ => Icons.devices_other_outlined,
      };
}

/// Niveau d'accès obtenu sur l'appareil, correspond à `DeviceAccess`.
class DeviceAccessLevels {
  DeviceAccessLevels._();

  static const String full = 'full';
  static const String adbDebug = 'adb_debug';
  static const String adbUnauthorized = 'adb_unauthorized';
  static const String mtpLimited = 'mtp_limited';
  static const String smb = 'smb';
  static const String ssh = 'ssh';
  static const String none = 'none';

  static String label(String access) => switch (access) {
        full => 'Accès complet',
        adbDebug => 'Débogage USB autorisé',
        adbUnauthorized => 'Autorisation refusée',
        mtpLimited => 'MTP, accès limité',
        smb => 'Partage réseau',
        ssh => 'SSH',
        none => 'Inaccessible',
        _ => access,
      };
}

class DeviceInfo {
  const DeviceInfo({
    required this.id,
    required this.kind,
    required this.label,
    required this.access,
    this.mountPoint,
    this.filesystem,
    this.totalBytes,
    this.usedBytes,
    this.model,
    this.scannable = true,
    this.blockedReason,
    this.details = const {},
  });

  final String id;
  final String kind;
  final String label;
  final String access;
  final String? mountPoint;
  final String? filesystem;
  final int? totalBytes;
  final int? usedBytes;
  final String? model;
  final bool scannable;

  /// Raison, rédigée par le backend, pour laquelle le scan n'est pas possible.
  /// Affichée telle quelle : elle contient la marche à suivre.
  final String? blockedReason;
  final Map<String, dynamic> details;

  /// Un scan de fichiers est possible dès qu'un point de montage est lisible.
  bool get canScanFiles => scannable && mountPoint != null;

  /// Vrai pour un Android dont le débogage USB est utilisable.
  bool get hasAdb => access == DeviceAccessLevels.adbDebug;

  double? get usageRatio {
    if (totalBytes == null || usedBytes == null || totalBytes == 0) return null;
    return usedBytes! / totalBytes!;
  }

  factory DeviceInfo.fromJson(Map<String, dynamic> json) => DeviceInfo(
        id: json['id'] as String? ?? '',
        kind: json['kind'] as String? ?? DeviceKinds.removable,
        label: json['label'] as String? ?? 'Appareil',
        access: json['access'] as String? ?? DeviceAccessLevels.none,
        mountPoint: json['mount_point'] as String?,
        filesystem: json['filesystem'] as String?,
        totalBytes: (json['total_bytes'] as num?)?.toInt(),
        usedBytes: (json['used_bytes'] as num?)?.toInt(),
        model: json['model'] as String?,
        scannable: json['scannable'] as bool? ?? true,
        blockedReason: json['blocked_reason'] as String?,
        details: (json['details'] as Map?)?.cast<String, dynamic>() ?? const {},
      );
}

/// Application Android analysée (section 4.2 de la spec).
class AndroidApp {
  const AndroidApp({
    required this.package,
    this.label,
    this.versionName,
    this.systemApp = false,
    this.apkPath,
    this.sha256,
    this.permissions = const [],
    this.dangerousPermissions = const [],
    this.riskScore = 0,
    this.severity = 'clean',
    this.signatureIssuer,
    this.notes = const [],
  });

  final String package;
  final String? label;
  final String? versionName;
  final bool systemApp;
  final String? apkPath;
  final String? sha256;
  final List<String> permissions;
  final List<String> dangerousPermissions;
  final int riskScore;
  final String severity;
  final String? signatureIssuer;

  /// Explications lisibles produites par l'heuristique de risque.
  final List<String> notes;

  String get displayName => label ?? package;

  factory AndroidApp.fromJson(Map<String, dynamic> json) => AndroidApp(
        package: json['package'] as String? ?? '',
        label: json['label'] as String?,
        versionName: json['version_name'] as String?,
        systemApp: json['system_app'] as bool? ?? false,
        apkPath: json['apk_path'] as String?,
        sha256: json['sha256'] as String?,
        permissions:
            (json['permissions'] as List?)?.map((e) => e.toString()).toList() ??
                const [],
        dangerousPermissions: (json['dangerous_permissions'] as List?)
                ?.map((e) => e.toString())
                .toList() ??
            const [],
        riskScore: (json['risk_score'] as num?)?.toInt() ?? 0,
        severity: json['severity'] as String? ?? 'clean',
        signatureIssuer: json['signature_issuer'] as String?,
        notes:
            (json['notes'] as List?)?.map((e) => e.toString()).toList() ??
                const [],
      );
}

/// Ce que la machine hôte sait faire (/api/devices/capabilities).
/// Sert à griser les actions impossibles au lieu de les laisser échouer.
class HostCapabilities {
  const HostCapabilities({
    this.platform = '',
    this.adb = false,
    this.lsblk = false,
    this.smbclient = false,
    this.ssh = false,
    this.windowsAgent = false,
  });

  final String platform;
  final bool adb;
  final bool lsblk;
  final bool smbclient;
  final bool ssh;
  final bool windowsAgent;

  factory HostCapabilities.fromJson(Map<String, dynamic> json) =>
      HostCapabilities(
        platform: json['platform'] as String? ?? '',
        adb: json['adb'] as bool? ?? false,
        lsblk: json['lsblk'] as bool? ?? false,
        smbclient: json['smbclient'] as bool? ?? false,
        ssh: json['ssh'] as bool? ?? false,
        windowsAgent: json['windows_agent'] as bool? ?? false,
      );
}
