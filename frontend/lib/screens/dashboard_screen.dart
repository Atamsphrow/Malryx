import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/scan_result.dart';
import '../state/app_state.dart';
import '../theme/app_theme.dart';
import '../utils/formatters.dart';
import '../widgets/common.dart';

/// Tableau de bord : état de protection, chiffres clés, moteurs, historique.
class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key, required this.onNavigate});

  /// Permet aux actions rapides d'ouvrir un autre onglet.
  final void Function(int index) onNavigate;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();

    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        _ProtectionHeader(onNavigate: onNavigate),
        const SizedBox(height: 20),
        _StatsGrid(),
        const SizedBox(height: 20),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(flex: 3, child: _EnginesCard()),
            const SizedBox(width: 20),
            Expanded(flex: 4, child: _HistoryCard(onNavigate: onNavigate)),
          ],
        ),
        if (state.isDevelopmentPlatform) ...[
          const SizedBox(height: 20),
          NoticeBanner(
            message:
                'Backend lancé sur ${state.health!.platform}, pas sur Linux. '
                'Le scan de fichiers, les empreintes et les heuristiques '
                'fonctionnent ; ClamAV, ADB, les montages et les points de '
                'démarrage sont inertes hors Debian.',
            icon: Icons.construction_outlined,
          ),
        ],
      ],
    );
  }
}

/// Grande carte d'état, façon « vous êtes protégé / attention ».
class _ProtectionHeader extends StatelessWidget {
  const _ProtectionHeader({required this.onNavigate});

  final void Function(int index) onNavigate;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final quarantined = state.stats.quarantineActive;
    final scanning = state.activeScan?.isActive ?? false;

    final (Color color, IconData icon, String title, String message) = switch ((
      scanning,
      quarantined > 0,
      state.stats.scansCompleted == 0,
    )) {
      (true, _, _) => (
          theme.colorScheme.primary,
          Icons.radar,
          'Analyse en cours',
          state.activeScan!.targetLabel,
        ),
      (_, true, _) => (
          SeverityPalette.medium,
          Icons.shield_outlined,
          '$quarantined élément${quarantined > 1 ? 's' : ''} en quarantaine',
          'Des fichiers ont été isolés. Examinez-les pour décider de leur sort.',
        ),
      (_, _, true) => (
          theme.colorScheme.onSurfaceVariant,
          Icons.shield_moon_outlined,
          'Aucun scan effectué',
          'Lancez une première analyse pour connaître l\'état de la machine.',
        ),
      _ => (
          SeverityPalette.clean,
          Icons.verified_user_outlined,
          'Aucune menace active',
          'Dernier scan ${formatRelative(state.stats.lastScanAt)}.',
        ),
    };

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Row(
          children: [
            Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.14),
                shape: BoxShape.circle,
                border: Border.all(color: color.withValues(alpha: 0.4), width: 2),
              ),
              child: Icon(icon, size: 34, color: color),
            ),
            const SizedBox(width: 24),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: theme.textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    message,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  if (scanning) ...[
                    const SizedBox(height: 14),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(6),
                      child: LinearProgressIndicator(
                        // `null` pendant l'énumération : barre indéterminée
                        // plutôt qu'un 0 % trompeur.
                        value: state.activeScan?.percent == null
                            ? null
                            : state.activeScan!.percent! / 100,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(width: 20),
            Column(
              children: [
                FilledButton.icon(
                  onPressed: () => onNavigate(1),
                  icon: Icon(scanning ? Icons.visibility : Icons.play_arrow),
                  label: Text(scanning ? 'Voir le scan' : 'Lancer un scan'),
                ),
                const SizedBox(height: 10),
                OutlinedButton.icon(
                  onPressed: scanning
                      ? null
                      : () async {
                          final started = await state.startScan(
                            type: ScanTypes.startup,
                          );
                          if (started) onNavigate(1);
                        },
                  icon: const Icon(Icons.bolt_outlined, size: 18),
                  label: const Text('Points de démarrage'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _StatsGrid extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final stats = state.stats;
    return ResponsiveTileGrid(
      children: [
        StatTile(
          label: 'Scans terminés',
          value: formatCount(stats.scansCompleted),
          icon: Icons.check_circle_outline,
          hint: 'Dernier ${formatRelative(stats.lastScanAt)}',
        ),
        StatTile(
          label: 'Fichiers analysés',
          value: formatCount(stats.filesScannedTotal),
          icon: Icons.description_outlined,
        ),
        StatTile(
          label: 'Menaces détectées',
          value: formatCount(stats.threatsTotal),
          icon: Icons.bug_report_outlined,
          accent: stats.threatsTotal > 0
              ? SeverityPalette.high
              : SeverityPalette.clean,
          hint: 'sur toute l\'historique',
        ),
        StatTile(
          label: 'En quarantaine',
          value: formatCount(stats.quarantineActive),
          icon: Icons.lock_outline,
          accent: stats.quarantineActive > 0
              ? SeverityPalette.medium
              : SeverityPalette.clean,
        ),
        StatTile(
          label: 'Appareils détectés',
          value: formatCount(state.devices.length),
          icon: Icons.devices_outlined,
        ),
        StatTile(
          label: 'Empreintes locales',
          value: formatCount(stats.localSignatures),
          icon: Icons.fingerprint,
        ),
      ],
    );
  }
}

class _EnginesCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final engines = state.health?.engines ?? const [];

    return SectionCard(
      title: 'Moteurs de détection',
      icon: Icons.memory_outlined,
      subtitle: state.health == null
          ? null
          : 'Backend ${state.health!.version} · '
              '${state.health!.root ? "root" : "utilisateur"}',
      action: IconButton(
        icon: const Icon(Icons.refresh, size: 18),
        tooltip: 'Réinterroger les moteurs',
        onPressed: state.refreshHealth,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (final engine in engines)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: Icon(
                      engine.available
                          ? Icons.check_circle
                          : Icons.remove_circle_outline,
                      size: 16,
                      color: engine.available
                          ? SeverityPalette.clean
                          : theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Text(engine.label,
                                style: theme.textTheme.bodyMedium),
                            if (engine.version != null) ...[
                              const SizedBox(width: 6),
                              Text(
                                'v${engine.version}',
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ],
                            if (engine.signatures != null) ...[
                              const SizedBox(width: 6),
                              Text(
                                '· ${formatCount(engine.signatures!)} règles',
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ],
                          ],
                        ),
                        // Le backend rédige ici la marche à suivre
                        // (« sudo apt install clamav-daemon »), on l'affiche
                        // sans la reformuler.
                        if (engine.detail != null)
                          Padding(
                            padding: const EdgeInsets.only(top: 2),
                            child: Text(
                              engine.detail!,
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          if (engines.isEmpty)
            Text(
              'État des moteurs indisponible.',
              style: theme.textTheme.bodySmall,
            ),
        ],
      ),
    );
  }
}

class _HistoryCard extends StatelessWidget {
  const _HistoryCard({required this.onNavigate});

  final void Function(int index) onNavigate;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final history = state.history.take(7).toList();

    return SectionCard(
      title: 'Scans récents',
      icon: Icons.history,
      action: IconButton(
        icon: const Icon(Icons.refresh, size: 18),
        tooltip: 'Rafraîchir',
        onPressed: state.refreshHistory,
      ),
      child: history.isEmpty
          ? Padding(
              padding: const EdgeInsets.symmetric(vertical: 20),
              child: Text(
                'Aucun scan pour le moment.',
                style: theme.textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
            )
          : Column(
              children: [
                for (final scan in history)
                  ListTile(
                    contentPadding:
                        const EdgeInsets.symmetric(horizontal: 8),
                    dense: true,
                    leading: Icon(
                      scan.threatsCount > 0
                          ? SeverityPalette.iconOf(scan.maxSeverity)
                          : Icons.check_circle_outline,
                      size: 20,
                      color: scan.threatsCount > 0
                          ? SeverityPalette.of(scan.maxSeverity)
                          : SeverityPalette.clean,
                    ),
                    title: Text(
                      shortenPath(scan.targetLabel, maxLength: 52),
                      style: theme.textTheme.bodyMedium,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    subtitle: Text(
                      '${ScanTypes.label(scan.type)} · '
                      '${formatCount(scan.filesScanned)} fichiers · '
                      '${formatSeconds(scan.durationSeconds)} · '
                      '${formatRelative(scan.startedAt)}',
                      style: theme.textTheme.bodySmall,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    trailing: scan.threatsCount > 0
                        ? Text(
                            '${scan.threatsCount}',
                            style: theme.textTheme.titleMedium?.copyWith(
                              color: SeverityPalette.of(scan.maxSeverity),
                              fontWeight: FontWeight.w600,
                            ),
                          )
                        : null,
                    onTap: () async {
                      await state.openScan(scan.id);
                      onNavigate(1);
                    },
                  ),
              ],
            ),
    );
  }
}
