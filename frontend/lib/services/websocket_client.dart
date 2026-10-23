import 'dart:async';
import 'dart:convert';

import 'package:web_socket_channel/web_socket_channel.dart';

/// Types d'évènements émis par le backend (`backend/core/events.py`).
class EventTypes {
  EventTypes._();

  static const String hello = 'hello';
  static const String scanStarted = 'scan.started';
  static const String scanProgress = 'scan.progress';
  static const String scanThreat = 'scan.threat';
  static const String scanFinished = 'scan.finished';
  static const String scanError = 'scan.error';
  static const String deviceConnected = 'device.connected';
  static const String deviceDisconnected = 'device.disconnected';
  static const String quarantineChanged = 'quarantine.changed';
}

/// Un évènement temps réel reçu du backend.
class BackendEvent {
  const BackendEvent(this.type, this.data, this.timestamp);

  final String type;
  final Map<String, dynamic> data;
  final DateTime timestamp;

  String? get scanId => data['scan_id'] as String?;

  factory BackendEvent.fromJson(Map<String, dynamic> json) => BackendEvent(
        json['type'] as String? ?? '',
        (json['data'] as Map?)?.cast<String, dynamic>() ?? const {},
        json['ts'] is num
            ? DateTime.fromMillisecondsSinceEpoch(
                ((json['ts'] as num) * 1000).round())
            : DateTime.now(),
      );
}

/// Client WebSocket vers /ws, avec reconnexion automatique.
///
/// La progression de scan est éphémère : après une coupure, il ne sert à rien
/// de rejouer les évènements manqués. On se reconnecte, et l'appelant
/// resynchronise l'état via `GET /api/scans/{id}/progress`, d'où le callback
/// `onReconnected`.
class WebSocketClient {
  WebSocketClient({
    this.host = '127.0.0.1',
    this.port = 8765,
    this.onReconnected,
  });

  final String host;
  final int port;

  /// Appelé après chaque reconnexion réussie, pour resynchroniser l'état.
  final void Function()? onReconnected;

  final _controller = StreamController<BackendEvent>.broadcast();
  WebSocketChannel? _channel;
  StreamSubscription<dynamic>? _subscription;
  Timer? _reconnectTimer;
  int _attempt = 0;
  bool _disposed = false;
  bool _everConnected = false;

  /// Flux des évènements. Diffusé : plusieurs écrans peuvent s'y abonner.
  Stream<BackendEvent> get events => _controller.stream;

  bool get isConnected => _channel != null;

  /// Évènements d'un scan précis, filtrés côté client.
  Stream<BackendEvent> eventsForScan(String scanId) =>
      events.where((e) => e.scanId == scanId);

  void connect() {
    if (_disposed || _channel != null) return;
    final uri = Uri.parse('ws://$host:$port/ws');
    try {
      final channel = WebSocketChannel.connect(uri);
      _channel = channel;
      _subscription = channel.stream.listen(
        _onMessage,
        onError: (Object error) => _scheduleReconnect(error),
        onDone: () => _scheduleReconnect('connexion fermée'),
        cancelOnError: true,
      );
    } catch (error) {
      _scheduleReconnect(error);
    }
  }

  void _onMessage(dynamic raw) {
    if (_attempt > 0 || !_everConnected) {
      // Premier message reçu : la connexion est réellement établie. On ne le
      // signale qu'après une coupure, pour éviter un rafraîchissement inutile
      // au tout premier démarrage.
      final wasReconnect = _everConnected;
      _everConnected = true;
      _attempt = 0;
      if (wasReconnect) onReconnected?.call();
    }
    try {
      final decoded = jsonDecode(raw as String);
      if (decoded is Map) {
        _controller.add(
          BackendEvent.fromJson(decoded.cast<String, dynamic>()),
        );
      }
    } catch (_) {
      // Message illisible : on l'ignore plutôt que de casser le flux.
    }
  }

  void _scheduleReconnect(Object cause) {
    _subscription?.cancel();
    _subscription = null;
    _channel = null;
    if (_disposed) return;
    // Recul exponentiel plafonné à 10 s : le backend local redémarre vite,
    // mais on n'inonde pas les logs s'il est définitivement tombé.
    final seconds = (1 << _attempt.clamp(0, 3)).clamp(1, 10);
    _attempt++;
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(Duration(seconds: seconds), connect);
  }

  Future<void> dispose() async {
    _disposed = true;
    _reconnectTimer?.cancel();
    await _subscription?.cancel();
    await _channel?.sink.close();
    await _controller.close();
  }
}
