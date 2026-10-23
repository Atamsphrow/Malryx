import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/device_info.dart';
import '../models/quarantine_entry.dart';
import '../models/scan_result.dart';

/// Erreur renvoyée par le backend, avec le message rédigé côté Python.
///
/// Ces messages sont écrits pour être affichés tels quels (ils contiennent la
/// marche à suivre : « installez adb », « acceptez l'empreinte RSA »…), donc
/// l'interface les montre sans les reformuler.
class ApiException implements Exception {
  ApiException(this.statusCode, this.detail);

  final int statusCode;
  final String detail;

  @override
  String toString() => detail;
}

/// Le backend n'est pas joignable : pas encore démarré, ou tombé.
class BackendUnavailable implements Exception {
  BackendUnavailable(this.cause);

  final String cause;

  @override
  String toString() =>
      'Le service Malryx ne répond pas. Vérifiez qu\'il est démarré ($cause).';
}

/// Client REST vers le backend local.
class ApiClient {
  ApiClient({
    this.host = '127.0.0.1',
    this.port = 8765,
    http.Client? client,
  }) : _client = client ?? http.Client();

  final String host;
  final int port;
  final http.Client _client;

  static const Duration _timeout = Duration(seconds: 30);

  /// Les scans distants (SSH, SMB) peuvent être longs : on leur laisse
  /// nettement plus de marge qu'un appel ordinaire.
  static const Duration _longTimeout = Duration(minutes: 20);

  String get baseUrl => 'http://$host:$port';

  Uri _uri(String path, [Map<String, dynamic>? query]) => Uri.http(
        '$host:$port',
        path,
        query?.map((k, v) => MapEntry(k, v.toString())),
      );

  void dispose() => _client.close();

  // -- primitives --------------------------------------------------------- //

  Future<dynamic> _send(
    String method,
    String path, {
    Map<String, dynamic>? query,
    Object? body,
    Duration? timeout,
  }) async {
    final uri = _uri(path, query);
    final request = http.Request(method, uri)
      ..headers['accept'] = 'application/json';
    if (body != null) {
      request.headers['content-type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    http.Response response;
    try {
      final streamed =
          await _client.send(request).timeout(timeout ?? _timeout);
      response = await http.Response.fromStream(streamed);
    } on TimeoutException {
      throw BackendUnavailable('délai dépassé sur $method $path');
    } catch (error) {
      throw BackendUnavailable(error.toString());
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      if (response.bodyBytes.isEmpty) return null;
      return jsonDecode(utf8.decode(response.bodyBytes));
    }
    throw ApiException(response.statusCode, _extractDetail(response));
  }

  /// FastAPI renvoie `{"detail": ...}`, où `detail` est soit une chaîne, soit
  /// la liste d'erreurs de validation de Pydantic.
  String _extractDetail(http.Response response) {
    try {
      final decoded = jsonDecode(utf8.decode(response.bodyBytes));
      final detail = decoded is Map ? decoded['detail'] : null;
      if (detail is String) return detail;
      if (detail is List && detail.isNotEmpty) {
        return detail
            .map((e) => e is Map ? (e['msg'] ?? e).toString() : e.toString())
            .join(' ; ');
      }
    } catch (_) {
      // Corps non JSON : on retombe sur le code HTTP.
    }
    return 'Erreur HTTP ${response.statusCode}';
  }

  // -- système ------------------------------------------------------------ //

  Future<BackendHealth> health() async {
    final json = await _send('GET', '/api/health');
    return BackendHealth.fromJson((json as Map).cast<String, dynamic>());
  }

  /// Attend que le backend réponde, le temps que le sous-processus démarre.
  Future<BackendHealth> waitUntilReady({
    Duration total = const Duration(seconds: 30),
    Duration interval = const Duration(milliseconds: 400),
  }) async {
    final deadline = DateTime.now().add(total);
    Object? lastError;
    while (DateTime.now().isBefore(deadline)) {
      try {
        return await health();
      } catch (error) {
        lastError = error;
        await Future<void>.delayed(interval);
      }
    }
    throw BackendUnavailable(
      'aucune réponse après ${total.inSeconds} s ($lastError)',
    );
  }

  Future<DashboardStats> stats() async {
    final json = await _send('GET', '/api/stats');
    return DashboardStats.fromJson((json as Map).cast<String, dynamic>());
  }

  Future<Map<String, dynamic>> settings() async {
    final json = await _send('GET', '/api/settings');
    return (json as Map).cast<String, dynamic>();
  }

  Future<Map<String, dynamic>> updateSettings(
      Map<String, dynamic> updates) async {
    final json = await _send('PUT', '/api/settings', body: updates);
    return (json as Map).cast<String, dynamic>();
  }

  // -- scans -------------------------------------------------------------- //

  Future<ScanResult> startScan({
    required String type,
    List<String> targets = const [],
    String? deviceId,
    ScanOptions options = const ScanOptions(),
  }) async {
    final json = await _send('POST', '/api/scans', body: {
      'type': type,
      'targets': targets,
      'device_id': ?deviceId,
      'options': options.toJson(),
    });
    return ScanResult.fromJson((json as Map).cast<String, dynamic>());
  }

  Future<ScanResult> getScan(String scanId) async {
    final json = await _send('GET', '/api/scans/$scanId');
    return ScanResult.fromJson((json as Map).cast<String, dynamic>());
  }

  Future<ScanProgress> getProgress(String scanId) async {
    final json = await _send('GET', '/api/scans/$scanId/progress');
    return ScanProgress.fromJson((json as Map).cast<String, dynamic>());
  }

  /// Rend les scans actifs et l'historique en un appel.
  Future<({List<ScanSummary> active, List<ScanSummary> history})> listScans({
    int limit = 50,
  }) async {
    final json = await _send('GET', '/api/scans', query: {'limit': limit});
    final map = (json as Map).cast<String, dynamic>();
    List<ScanSummary> parse(String key) =>
        ((map[key] as List?) ?? const [])
            .map((e) =>
                ScanSummary.fromJson((e as Map).cast<String, dynamic>()))
            .toList();
    return (active: parse('active'), history: parse('history'));
  }

  Future<void> cancelScan(String scanId) =>
      _send('POST', '/api/scans/$scanId/cancel');

  Future<void> deleteScan(String scanId) =>
      _send('DELETE', '/api/scans/$scanId');

  // -- appareils ---------------------------------------------------------- //

  Future<List<DeviceInfo>> devices({bool includeLocal = true}) async {
    final json = await _send('GET', '/api/devices',
        query: {'include_local': includeLocal});
    return ((json as List?) ?? const [])
        .map((e) => DeviceInfo.fromJson((e as Map).cast<String, dynamic>()))
        .toList();
  }

  Future<HostCapabilities> capabilities() async {
    final json = await _send('GET', '/api/devices/capabilities');
    return HostCapabilities.fromJson((json as Map).cast<String, dynamic>());
  }

  Future<List<Map<String, String>>> autorunFindings(String mountPoint) async {
    final json = await _send('GET', '/api/devices/autorun',
        query: {'mount_point': mountPoint});
    final findings = ((json as Map)['findings'] as List?) ?? const [];
    return findings
        .map((e) => (e as Map).map((k, v) => MapEntry('$k', '$v')))
        .toList();
  }

  Future<List<AndroidApp>> androidApps(
    String serial, {
    bool includeSystem = false,
    bool analyze = true,
  }) async {
    final json = await _send(
      'GET',
      '/api/devices/android/$serial/apps',
      query: {'include_system': includeSystem, 'analyze': analyze},
      // L'analyse interroge dumpsys pour chaque paquet : c'est long.
      timeout: const Duration(minutes: 5),
    );
    return ((json as List?) ?? const [])
        .map((e) => AndroidApp.fromJson((e as Map).cast<String, dynamic>()))
        .toList();
  }

  Future<String> uninstallAndroidApp(String serial, String package) async {
    final json = await _send(
      'POST',
      '/api/devices/android/$serial/apps/$package/uninstall',
      timeout: const Duration(minutes: 2),
    );
    return ((json as Map)['output'] as String?) ?? 'Désinstallé';
  }

  Future<void> revokeAndroidPermission(
    String serial,
    String package,
    String permission,
  ) =>
      _send(
        'POST',
        '/api/devices/android/$serial/apps/$package/revoke',
        body: {'permission': permission},
      );

  Future<DeviceInfo> probeSsh(String host, {String? user, int port = 22}) async {
    final json = await _send('POST', '/api/devices/remote/ssh/probe',
        body: {'host': host, 'user': user, 'port': port});
    return DeviceInfo.fromJson((json as Map).cast<String, dynamic>());
  }

  Future<Map<String, dynamic>> sshHashScan({
    required String host,
    required List<String> paths,
    String? user,
    int port = 22,
  }) async {
    final json = await _send(
      'POST',
      '/api/devices/remote/ssh/scan',
      body: {'host': host, 'paths': paths, 'user': user, 'port': port},
      timeout: _longTimeout,
    );
    return (json as Map).cast<String, dynamic>();
  }

  Future<Map<String, dynamic>> smbShares(String host, {String? user}) async {
    final json = await _send('POST', '/api/devices/remote/smb/shares',
        body: {'host': host, 'user': user});
    return (json as Map).cast<String, dynamic>();
  }

  Future<List<String>> windowsTargets(String mountPoint) async {
    final json = await _send('GET', '/api/devices/remote/windows/targets',
        query: {'mount_point': mountPoint});
    return (((json as Map)['targets'] as List?) ?? const [])
        .map((e) => e.toString())
        .toList();
  }

  // -- quarantaine -------------------------------------------------------- //

  Future<List<QuarantineEntry>> quarantine({
    bool includeInactive = false,
  }) async {
    final json = await _send('GET', '/api/quarantine',
        query: {'include_inactive': includeInactive});
    return ((json as List?) ?? const [])
        .map((e) => QuarantineEntry.fromJson((e as Map).cast<String, dynamic>()))
        .toList();
  }

  Future<QuarantineEntry> quarantineFile(
    String path, {
    String? threatName,
    String severity = 'medium',
    bool force = false,
  }) async {
    final json = await _send(
      'POST',
      '/api/quarantine',
      query: {'force': force},
      body: {
        'path': path,
        'threat_name': threatName,
        'severity': severity,
      },
    );
    return QuarantineEntry.fromJson((json as Map).cast<String, dynamic>());
  }

  Future<String> restoreQuarantine(String id, {String? destination}) async {
    final json = await _send('POST', '/api/quarantine/$id/restore',
        body: {'destination': destination});
    return ((json as Map)['path'] as String?) ?? '';
  }

  Future<void> deleteQuarantine(String id) =>
      _send('DELETE', '/api/quarantine/$id');

  // -- signatures --------------------------------------------------------- //

  Future<int> importSignatures(String path) async {
    final json =
        await _send('POST', '/api/signatures/import', body: {'path': path});
    return ((json as Map)['imported'] as num?)?.toInt() ?? 0;
  }
}
