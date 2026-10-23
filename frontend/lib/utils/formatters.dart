import 'package:intl/intl.dart';

/// Formatage en français des tailles, durées et dates affichées dans l'UI.

final _decimal = NumberFormat.decimalPattern('fr_FR');
final _dateTime = DateFormat("d MMM y 'à' HH:mm", 'fr_FR');
final _timeOnly = DateFormat('HH:mm:ss', 'fr_FR');

/// Taille lisible, en unités binaires (Kio = 1024 o), comme le backend.
String formatBytes(int? bytes) {
  if (bytes == null) return '—';
  if (bytes < 1024) return '$bytes o';
  const units = ['Kio', 'Mio', 'Gio', 'Tio'];
  var value = bytes / 1024;
  var index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }
  final digits = value >= 100 ? 0 : 1;
  return '${value.toStringAsFixed(digits)} ${units[index]}';
}

String formatCount(int value) => _decimal.format(value);

String formatDateTime(DateTime? date) =>
    date == null ? '—' : _dateTime.format(date.toLocal());

String formatTime(DateTime date) => _timeOnly.format(date.toLocal());

/// Durée compacte : « 4 s », « 2 min 13 s », « 1 h 05 ».
String formatDuration(Duration duration) {
  final seconds = duration.inSeconds;
  if (seconds < 60) {
    final tenths = duration.inMilliseconds / 1000;
    return seconds < 10 ? '${tenths.toStringAsFixed(1)} s' : '$seconds s';
  }
  if (seconds < 3600) {
    return '${duration.inMinutes} min ${(seconds % 60).toString().padLeft(2, '0')} s';
  }
  final minutes = duration.inMinutes % 60;
  return '${duration.inHours} h ${minutes.toString().padLeft(2, '0')}';
}

String formatSeconds(double seconds) =>
    formatDuration(Duration(milliseconds: (seconds * 1000).round()));

/// Écart relatif : « il y a 5 min », « il y a 2 j ».
String formatRelative(DateTime? date) {
  if (date == null) return 'jamais';
  final delta = DateTime.now().difference(date);
  if (delta.inSeconds < 60) return "à l'instant";
  if (delta.inMinutes < 60) return 'il y a ${delta.inMinutes} min';
  if (delta.inHours < 24) return 'il y a ${delta.inHours} h';
  if (delta.inDays < 30) return 'il y a ${delta.inDays} j';
  return formatDateTime(date);
}

/// Raccourcit un chemin trop long en gardant le début et la fin, qui portent
/// l'information utile (la racine et le nom du fichier).
String shortenPath(String path, {int maxLength = 60}) {
  if (path.length <= maxLength) return path;
  final keep = (maxLength - 3) ~/ 2;
  return '${path.substring(0, keep)}…${path.substring(path.length - keep)}';
}

/// Permissions POSIX en notation symbolique, pour la quarantaine (« rwxr-xr-x »).
String formatMode(int? mode) {
  if (mode == null) return '—';
  const flags = ['r', 'w', 'x'];
  final buffer = StringBuffer();
  for (var shift = 6; shift >= 0; shift -= 3) {
    final part = (mode >> shift) & 0x7;
    for (var bit = 0; bit < 3; bit++) {
      buffer.write((part & (4 >> bit)) != 0 ? flags[bit] : '-');
    }
  }
  return buffer.toString();
}
