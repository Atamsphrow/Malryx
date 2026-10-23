import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'screens/dashboard_screen.dart';
import 'screens/devices_screen.dart';
import 'screens/local_scan_screen.dart';
import 'screens/quarantine_screen.dart';
import 'screens/settings_screen.dart';
import 'state/app_state.dart';
import 'theme/app_theme.dart';
import 'widgets/common.dart';

void main() {
  runApp(const MalryxApp());
}

class MalryxApp extends StatelessWidget {
  const MalryxApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => AppState()..initialize(),
      child: Consumer<AppState>(
        builder: (context, state, _) {
          return MaterialApp(
            title: 'Malryx',
            debugShowCheckedModeBanner: false,
            // Mode sombre forcé : aucun ThemeMode.system, aucun thème clair.
            // C'est un choix de conception, pas un oubli.
            theme: MalryxTheme.dark(_seedFrom(state)),
            home: const _AppShell(),
          );
        },
      ),
    );
  }

  /// Couleur d'accent issue des réglages du backend, avec repli sur le cyan.
  Color _seedFrom(AppState state) {
    final raw = state.settings['accent_color'];
    if (raw is String) {
      final hex = raw.replaceAll('#', '');
      final value = int.tryParse(hex, radix: 16);
      if (value != null) {
        // Format attendu : AARRGGBB. Si seul RRGGBB est fourni, on force
        // l'opacité complète.
        return Color(hex.length == 6 ? 0xFF000000 | value : value);
      }
    }
    return MalryxTheme.defaultSeed;
  }
}

/// Coquille de l'application : rail de navigation à gauche, écran à droite.
class _AppShell extends StatefulWidget {
  const _AppShell();

  @override
  State<_AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<_AppShell> {
  int _index = 0;

  static const List<({String label, IconData icon, IconData selectedIcon})>
      _destinations = [
    (
      label: 'Tableau de bord',
      icon: Icons.dashboard_outlined,
      selectedIcon: Icons.dashboard
    ),
    (label: 'Scan', icon: Icons.radar_outlined, selectedIcon: Icons.radar),
    (
      label: 'Appareils',
      icon: Icons.devices_outlined,
      selectedIcon: Icons.devices
    ),
    (
      label: 'Quarantaine',
      icon: Icons.lock_outline,
      selectedIcon: Icons.lock
    ),
    (
      label: 'Réglages',
      icon: Icons.settings_outlined,
      selectedIcon: Icons.settings
    ),
  ];

  void _navigate(int index) => setState(() => _index = index);

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();

    if (state.phase == BackendPhase.starting) {
      return const _StartupScreen();
    }
    if (state.phase == BackendPhase.failed) {
      return _StartupFailedScreen(message: state.startupError ?? 'Erreur inconnue');
    }

    return Scaffold(
      body: Row(
        children: [
          _NavigationSidebar(
            index: _index,
            destinations: _destinations,
            onSelect: _navigate,
          ),
          const VerticalDivider(width: 1),
          Expanded(
            child: Column(
              children: [
                _TopBar(title: _destinations[_index].label),
                if (state.notice != null)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(24, 0, 24, 0),
                    child: NoticeBanner(
                      message: state.notice!,
                      isError: state.noticeIsError,
                      onDismiss: state.clearNotice,
                    ),
                  ),
                Expanded(child: _screenFor(_index)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _screenFor(int index) => switch (index) {
        0 => DashboardScreen(onNavigate: _navigate),
        1 => const LocalScanScreen(),
        2 => DevicesScreen(onNavigate: _navigate),
        3 => const QuarantineScreen(),
        _ => const SettingsScreen(),
      };
}

class _NavigationSidebar extends StatelessWidget {
  const _NavigationSidebar({
    required this.index,
    required this.destinations,
    required this.onSelect,
  });

  final int index;
  final List<({String label, IconData icon, IconData selectedIcon})>
      destinations;
  final ValueChanged<int> onSelect;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = context.watch<AppState>();

    return NavigationRail(
      selectedIndex: index,
      onDestinationSelected: onSelect,
      labelType: NavigationRailLabelType.all,
      minWidth: 96,
      leading: Padding(
        padding: const EdgeInsets.only(top: 20, bottom: 24),
        child: Column(
          children: [
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    theme.colorScheme.primary,
                    theme.colorScheme.tertiary,
                  ],
                ),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(Icons.shield_outlined,
                  color: theme.colorScheme.onPrimary, size: 24),
            ),
            const SizedBox(height: 8),
            Text(
              'Malryx',
              style: theme.textTheme.labelLarge?.copyWith(
                fontWeight: FontWeight.w700,
                letterSpacing: 0.5,
              ),
            ),
          ],
        ),
      ),
      trailing: Expanded(
        child: Align(
          alignment: Alignment.bottomCenter,
          child: Padding(
            padding: const EdgeInsets.only(bottom: 20),
            child: Tooltip(
              message: state.wsConnected
                  ? 'Flux temps réel connecté'
                  : 'Flux temps réel interrompu, reconnexion en cours',
              child: Icon(
                state.wsConnected ? Icons.sensors : Icons.sensors_off,
                size: 18,
                color: state.wsConnected
                    ? SeverityPalette.clean
                    : SeverityPalette.medium,
              ),
            ),
          ),
        ),
      ),
      destinations: [
        for (final destination in destinations)
          NavigationRailDestination(
            icon: _DestinationIcon(
              icon: destination.icon,
              label: destination.label,
            ),
            selectedIcon: _DestinationIcon(
              icon: destination.selectedIcon,
              label: destination.label,
            ),
            label: Text(destination.label),
          ),
      ],
    );
  }
}

/// Icône de navigation, avec un badge sur les entrées qui demandent attention.
class _DestinationIcon extends StatelessWidget {
  const _DestinationIcon({required this.icon, required this.label});

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final count = switch (label) {
      'Quarantaine' => state.stats.quarantineActive,
      'Appareils' => state.devices.where((d) => d.kind != 'local_host').length,
      _ => 0,
    };
    final scanning = label == 'Scan' && (state.activeScan?.isActive ?? false);

    if (scanning) {
      return const SizedBox(
        width: 24,
        height: 24,
        child: CircularProgressIndicator(strokeWidth: 2.5),
      );
    }
    if (count == 0) return Icon(icon);
    return Badge(
      label: Text('$count'),
      child: Icon(icon),
    );
  }
}

class _TopBar extends StatelessWidget {
  const _TopBar({required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 18),
      child: Row(
        children: [
          Text(title, style: theme.textTheme.headlineSmall),
          const Spacer(),
          if (state.health != null && !state.health!.root)
            Padding(
              padding: const EdgeInsets.only(right: 12),
              child: Tooltip(
                message: 'Lancé sans privilèges root : les fichiers système '
                    'protégés ne pourront pas être lus. Lancez avec sudo pour '
                    'un scan complet.',
                child: Chip(
                  avatar: const Icon(Icons.person_outline, size: 16),
                  label: const Text('Utilisateur'),
                  visualDensity: VisualDensity.compact,
                ),
              ),
            ),
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Tout rafraîchir',
            onPressed: state.refreshAll,
          ),
        ],
      ),
    );
  }
}

class _StartupScreen extends StatelessWidget {
  const _StartupScreen();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    theme.colorScheme.primary,
                    theme.colorScheme.tertiary,
                  ],
                ),
                borderRadius: BorderRadius.circular(18),
              ),
              child: Icon(Icons.shield_outlined,
                  size: 38, color: theme.colorScheme.onPrimary),
            ),
            const SizedBox(height: 24),
            Text('Malryx', style: theme.textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
              'Démarrage du moteur d\'analyse…',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 28),
            const SizedBox(
              width: 200,
              child: LinearProgressIndicator(),
            ),
          ],
        ),
      ),
    );
  }
}

class _StartupFailedScreen extends StatelessWidget {
  const _StartupFailedScreen({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final state = context.read<AppState>();
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 620),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.error_outline,
                    size: 48, color: SeverityPalette.critical),
                const SizedBox(height: 20),
                Text(
                  'Le moteur d\'analyse n\'a pas démarré',
                  style: Theme.of(context).textTheme.headlineSmall,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: SelectableText(
                    message,
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: state.initialize,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Réessayer'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
