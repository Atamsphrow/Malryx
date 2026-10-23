import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/device_info.dart';
import '../models/scan_result.dart';
import '../state/app_state.dart';
import '../theme/app_theme.dart';
import '../utils/formatters.dart';
import '../widgets/common.dart';

/// Appareils connectés : machine locale, clés USB, Android, volumes Windows,
/// machines Linux distantes (sections 4.2 à 4.5 de la spec).
class DevicesScreen extends StatelessWidget {
  const DevicesScreen({super.key, required this.onNavigate});

  final void Function(int index) onNavigate;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);

    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Row(
          children: [
            Expanded(
              child: Text('Appareils détectés',
                  style: theme.textTheme.titleLarge),
            ),
            OutlinedButton.icon(
              onPressed: state.refreshDevices,
              icon: const Icon(Icons.refresh, size: 18),
              label: const Text('Rechercher'),
            ),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          'Les médias amovibles sont détectés automatiquement à l\'insertion.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 20),
        if (state.devices.isEmpty)
          EmptyState(
            icon: Icons.usb_off_outlined,
            title: 'Aucun appareil',
            message: 'Branchez une clé USB ou un téléphone, puis relancez la '
                'recherche.',
          )
        else
          for (final device in state.devices)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: _DeviceCard(device: device, onNavigate: onNavigate),
            ),
        const SizedBox(height: 12),
        _CapabilitiesCard(),
        const SizedBox(height: 12),
        _RemoteLinuxCard(),
      ],
    );
  }
}

class _DeviceCard extends StatelessWidget {
  const _DeviceCard({required this.device, required this.onNavigate});

  final DeviceInfo device;
  final void Function(int index) onNavigate;

  @override
  Widget build(BuildContext context) {
    final state = context.read<AppState>();
    final theme = Theme.of(context);
    final ratio = device.usageRatio;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Container(
                  width: 46,
                  height: 46,
                  decoration: BoxDecoration(
                    color: theme.colorScheme.primary.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(DeviceKinds.icon(device.kind),
                      color: theme.colorScheme.primary),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(device.label, style: theme.textTheme.titleMedium),
                      const SizedBox(height: 2),
                      Text(
                        '${DeviceKinds.label(device.kind)} · '
                        '${DeviceAccessLevels.label(device.access)}'
                        '${device.filesystem != null ? " · ${device.filesystem}" : ""}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                if (device.canScanFiles)
                  FilledButton.icon(
                    onPressed: () async {
                      final type = switch (device.kind) {
                        DeviceKinds.removable => ScanTypes.usb,
                        DeviceKinds.windowsHost => ScanTypes.path,
                        _ => ScanTypes.path,
                      };
                      final started = await state.startScan(
                        type: type,
                        targets: [device.mountPoint!],
                        deviceId: device.id,
                      );
                      if (started) onNavigate(1);
                    },
                    icon: const Icon(Icons.radar, size: 18),
                    label: const Text('Analyser'),
                  ),
                if (device.hasAdb) ...[
                  const SizedBox(width: 10),
                  OutlinedButton.icon(
                    onPressed: () => _openAndroidApps(context, device),
                    icon: const Icon(Icons.apps, size: 18),
                    label: const Text('Applications'),
                  ),
                ],
              ],
            ),
            if (device.mountPoint != null) ...[
              const SizedBox(height: 14),
              Text(
                device.mountPoint!,
                style: theme.textTheme.bodySmall?.copyWith(
                  fontFamily: 'monospace',
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            if (ratio != null) ...[
              const SizedBox(height: 12),
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(value: ratio, minHeight: 6),
              ),
              const SizedBox(height: 6),
              Text(
                '${formatBytes(device.usedBytes)} utilisés sur '
                '${formatBytes(device.totalBytes)}',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            if (device.blockedReason != null) ...[
              const SizedBox(height: 14),
              NoticeBanner(
                message: device.blockedReason!,
                icon: Icons.info_outline,
              ),
            ],
            if (device.details['hint'] is String) ...[
              const SizedBox(height: 12),
              Text(
                device.details['hint'] as String,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            if (device.details['rooted_hint'] == true) ...[
              const SizedBox(height: 12),
              NoticeBanner(
                message: 'Cet appareil semble rooté. Ce n\'est pas une '
                    'infection, mais la surface d\'attaque est plus large.',
                icon: Icons.warning_amber_outlined,
              ),
            ],
          ],
        ),
      ),
    );
  }

  void _openAndroidApps(BuildContext context, DeviceInfo device) {
    showDialog<void>(
      context: context,
      builder: (_) => _AndroidAppsDialog(device: device),
    );
  }
}

/// Liste des applications d'un téléphone, triée par score de risque.
class _AndroidAppsDialog extends StatefulWidget {
  const _AndroidAppsDialog({required this.device});

  final DeviceInfo device;

  @override
  State<_AndroidAppsDialog> createState() => _AndroidAppsDialogState();
}

class _AndroidAppsDialogState extends State<_AndroidAppsDialog> {
  late Future<List<AndroidApp>> _future;
  bool _includeSystem = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  void _load() {
    _future = context
        .read<AppState>()
        .androidApps(widget.device.id, includeSystem: _includeSystem);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 760, maxHeight: 640),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Icon(Icons.smartphone_outlined,
                      color: theme.colorScheme.primary),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(widget.device.label,
                        style: theme.textTheme.titleMedium),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Switch(
                    value: _includeSystem,
                    onChanged: (value) => setState(() {
                      _includeSystem = value;
                      _load();
                    }),
                  ),
                  const SizedBox(width: 8),
                  Text('Inclure les applications système',
                      style: theme.textTheme.bodySmall),
                ],
              ),
              const Divider(height: 20),
              Expanded(
                child: FutureBuilder<List<AndroidApp>>(
                  future: _future,
                  builder: (context, snapshot) {
                    if (snapshot.connectionState == ConnectionState.waiting) {
                      return const Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            CircularProgressIndicator(),
                            SizedBox(height: 16),
                            Text('Lecture des permissions via ADB…'),
                          ],
                        ),
                      );
                    }
                    if (snapshot.hasError) {
                      return EmptyState(
                        icon: Icons.error_outline,
                        title: 'Lecture impossible',
                        message: '${snapshot.error}',
                      );
                    }
                    final apps = snapshot.data ?? const [];
                    if (apps.isEmpty) {
                      return const EmptyState(
                        icon: Icons.apps_outlined,
                        title: 'Aucune application',
                        message: 'Aucun paquet tiers trouvé sur cet appareil.',
                      );
                    }
                    return ListView.builder(
                      itemCount: apps.length,
                      itemBuilder: (context, index) =>
                          _AndroidAppTile(app: apps[index], serial: widget.device.id),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _AndroidAppTile extends StatelessWidget {
  const _AndroidAppTile({required this.app, required this.serial});

  final AndroidApp app;
  final String serial;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = context.read<AppState>();
    return ExpansionTile(
      leading: CircleAvatar(
        radius: 18,
        backgroundColor:
            SeverityPalette.of(app.severity).withValues(alpha: 0.18),
        child: Text(
          '${app.riskScore}',
          style: TextStyle(
            color: SeverityPalette.of(app.severity),
            fontWeight: FontWeight.w700,
            fontSize: 13,
          ),
        ),
      ),
      title: Text(app.displayName, style: theme.textTheme.bodyMedium),
      subtitle: Text(
        '${app.package}${app.versionName != null ? " · v${app.versionName}" : ""}',
        style: theme.textTheme.bodySmall,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: SeverityChip(severity: app.severity, compact: true),
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (app.notes.isNotEmpty) ...[
                Text('Pourquoi ce score', style: theme.textTheme.labelLarge),
                const SizedBox(height: 6),
                for (final note in app.notes)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Text('• $note', style: theme.textTheme.bodySmall),
                  ),
                const SizedBox(height: 12),
              ],
              if (app.dangerousPermissions.isNotEmpty) ...[
                Text(
                  '${app.dangerousPermissions.length} permission(s) sensible(s)',
                  style: theme.textTheme.labelLarge,
                ),
                const SizedBox(height: 6),
                Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: [
                    for (final permission in app.dangerousPermissions)
                      Chip(
                        label: Text(
                          permission.split('.').last,
                          style: const TextStyle(fontSize: 11),
                        ),
                        visualDensity: VisualDensity.compact,
                      ),
                  ],
                ),
                const SizedBox(height: 12),
              ],
              if (app.apkPath != null)
                DetailRow(label: 'APK', value: app.apkPath!, selectable: true),
              Align(
                alignment: Alignment.centerLeft,
                child: OutlinedButton.icon(
                  onPressed: () => _confirmUninstall(context, state),
                  icon: const Icon(Icons.delete_outline, size: 18),
                  label: const Text('Désinstaller du téléphone'),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  /// La désinstallation est distante et destructive : on confirme d'abord.
  Future<void> _confirmUninstall(BuildContext context, AppState state) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Désinstaller cette application ?'),
        content: Text(
          '${app.displayName} (${app.package}) sera supprimée du téléphone. '
          'Ses données seront perdues. Cette action est irréversible.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Annuler'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Désinstaller'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await state.uninstallAndroidApp(serial, app.package);
    }
  }
}

/// Ce que la machine sait faire : sert à expliquer pourquoi une action manque.
class _CapabilitiesCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final capabilities = context.watch<AppState>().capabilities;
    return SectionCard(
      title: 'Outils système disponibles',
      icon: Icons.build_outlined,
      subtitle: 'Les fonctions dont l\'outil manque sont grisées.',
      child: Wrap(
        spacing: 10,
        runSpacing: 10,
        children: [
          _tool('adb', capabilities.adb, 'Scan Android'),
          _tool('lsblk', capabilities.lsblk, 'Détection des médias'),
          _tool('smbclient', capabilities.smbclient, 'Partages Windows'),
          _tool('ssh', capabilities.ssh, 'Linux distant'),
        ],
      ),
    );
  }

  Widget _tool(String name, bool available, String purpose) {
    return Tooltip(
      message: available
          ? '$name présent : $purpose disponible'
          : '$name absent : $purpose indisponible',
      child: Chip(
        avatar: Icon(
          available ? Icons.check_circle : Icons.remove_circle_outline,
          size: 16,
          color: available ? SeverityPalette.clean : null,
        ),
        label: Text(name),
        visualDensity: VisualDensity.compact,
      ),
    );
  }
}

/// Connexion à une autre machine Linux par SSH (section 4.4).
class _RemoteLinuxCard extends StatefulWidget {
  @override
  State<_RemoteLinuxCard> createState() => _RemoteLinuxCardState();
}

class _RemoteLinuxCardState extends State<_RemoteLinuxCard> {
  final _hostController = TextEditingController();
  final _userController = TextEditingController();
  bool _busy = false;
  DeviceInfo? _probed;
  String? _error;

  @override
  void dispose() {
    _hostController.dispose();
    _userController.dispose();
    super.dispose();
  }

  Future<void> _probe() async {
    final host = _hostController.text.trim();
    if (host.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
      _probed = null;
    });
    try {
      final device = await context.read<AppState>().api.probeSsh(
            host,
            user: _userController.text.trim().isEmpty
                ? null
                : _userController.text.trim(),
          );
      if (mounted) setState(() => _probed = device);
    } catch (error) {
      if (mounted) setState(() => _error = '$error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SectionCard(
      title: 'Machine Linux distante',
      icon: Icons.dns_outlined,
      subtitle: 'Scan en lecture seule par SSH, sans rien installer à distance.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Expanded(
                flex: 3,
                child: TextField(
                  controller: _hostController,
                  decoration: const InputDecoration(
                    labelText: 'Hôte ou adresse IP',
                    hintText: '192.168.1.20',
                  ),
                  onSubmitted: (_) => _probe(),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                flex: 2,
                child: TextField(
                  controller: _userController,
                  decoration: const InputDecoration(
                    labelText: 'Utilisateur',
                    hintText: 'facultatif',
                  ),
                  onSubmitted: (_) => _probe(),
                ),
              ),
              const SizedBox(width: 12),
              FilledButton(
                onPressed: _busy ? null : _probe,
                child: _busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Tester'),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            'L\'authentification se fait par clé SSH uniquement : aucun mot de '
            'passe n\'est demandé ni stocké.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          if (_error != null) ...[
            const SizedBox(height: 12),
            NoticeBanner(message: _error!, isError: true),
          ],
          if (_probed != null) ...[
            const SizedBox(height: 12),
            NoticeBanner(
              message: _probed!.blockedReason ??
                  'Connecté : ${_probed!.label}. '
                      '${_probed!.details['kernel'] ?? ''}',
              isError: !_probed!.scannable,
              icon: _probed!.scannable
                  ? Icons.check_circle_outline
                  : Icons.error_outline,
            ),
          ],
        ],
      ),
    );
  }
}
