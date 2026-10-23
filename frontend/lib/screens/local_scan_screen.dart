import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/scan_result.dart';
import '../models/threat.dart';
import '../state/app_state.dart';
import '../theme/app_theme.dart';
import '../utils/formatters.dart';
import '../widgets/common.dart';
import '../widgets/threat_tile.dart';

/// Scan local : choix de la cible, options, progression temps réel, résultats.
///
/// L'écran a trois états : configuration, scan en cours, résultat. Ils sont
/// enchaînés dans une seule vue plutôt que dans des pages séparées, pour que
/// l'utilisateur garde le contexte de ce qu'il a lancé.
class LocalScanScreen extends StatefulWidget {
  const LocalScanScreen({super.key});

  @override
  State<LocalScanScreen> createState() => _LocalScanScreenState();
}

class _LocalScanScreenState extends State<LocalScanScreen> {
  final List<String> _targets = [];
  ScanOptions _options = const ScanOptions();
  String _scanType = ScanTypes.path;

  Future<void> _pickDirectory() async {
    final path = await getDirectoryPath(
      confirmButtonText: 'Analyser',
    );
    if (path != null && mounted) {
      setState(() {
        if (!_targets.contains(path)) _targets.add(path);
        _scanType = ScanTypes.path;
      });
    }
  }

  Future<void> _pickFiles() async {
    final files = await openFiles();
    if (files.isNotEmpty && mounted) {
      setState(() {
        for (final file in files) {
          if (!_targets.contains(file.path)) _targets.add(file.path);
        }
        _scanType = ScanTypes.path;
      });
    }
  }

  Future<void> _start(AppState state) async {
    await state.startScan(
      type: _scanType,
      targets: _scanType == ScanTypes.path ? _targets : const [],
      options: _options,
    );
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final active = state.activeScan;

    if (active != null) {
      return _ScanRunningView(scan: active);
    }
    if (state.selectedScan != null) {
      return _ScanResultView(result: state.selectedScan!);
    }
    return _buildConfiguration(context, state);
  }

  Widget _buildConfiguration(BuildContext context, AppState state) {
    final theme = Theme.of(context);
    final canStart = _scanType != ScanTypes.path || _targets.isNotEmpty;

    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        SectionCard(
          title: 'Que voulez-vous analyser ?',
          icon: Icons.travel_explore_outlined,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: [
                  _typeChoice(ScanTypes.path, 'Dossier ou fichier',
                      Icons.folder_outlined),
                  _typeChoice(ScanTypes.fullSystem, 'Système complet',
                      Icons.dns_outlined),
                  _typeChoice(ScanTypes.startup, 'Points de démarrage',
                      Icons.rocket_launch_outlined),
                  _typeChoice(ScanTypes.memory, 'Mémoire et processus',
                      Icons.memory_outlined),
                  _typeChoice(ScanTypes.packages, 'Paquets installés',
                      Icons.inventory_2_outlined),
                ],
              ),
              if (_scanType == ScanTypes.path) ...[
                const SizedBox(height: 18),
                Row(
                  children: [
                    OutlinedButton.icon(
                      onPressed: _pickDirectory,
                      icon: const Icon(Icons.folder_open, size: 18),
                      label: const Text('Ajouter un dossier'),
                    ),
                    const SizedBox(width: 10),
                    OutlinedButton.icon(
                      onPressed: _pickFiles,
                      icon: const Icon(Icons.insert_drive_file_outlined,
                          size: 18),
                      label: const Text('Ajouter des fichiers'),
                    ),
                  ],
                ),
                if (_targets.isNotEmpty) ...[
                  const SizedBox(height: 14),
                  for (final target in _targets)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 6),
                      child: Row(
                        children: [
                          Icon(Icons.subdirectory_arrow_right,
                              size: 16,
                              color: theme.colorScheme.onSurfaceVariant),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              target,
                              style: theme.textTheme.bodySmall?.copyWith(
                                fontFamily: 'monospace',
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          IconButton(
                            icon: const Icon(Icons.close, size: 16),
                            visualDensity: VisualDensity.compact,
                            tooltip: 'Retirer',
                            onPressed: () =>
                                setState(() => _targets.remove(target)),
                          ),
                        ],
                      ),
                    ),
                ],
              ],
              if (_scanType == ScanTypes.fullSystem) ...[
                const SizedBox(height: 16),
                NoticeBanner(
                  message:
                      'Le scan complet parcourt toute la racine. Les pseudo-'
                      'systèmes de fichiers (/proc, /sys, /dev) et la '
                      'quarantaine sont exclus. Comptez plusieurs dizaines de '
                      'minutes, et des fichiers illisibles sans droits root.',
                  icon: Icons.schedule,
                ),
              ],
              if (_scanType == ScanTypes.startup) ...[
                const SizedBox(height: 16),
                NoticeBanner(
                  message:
                      'Analyse des emplacements de persistance : cron, unités '
                      'systemd, init.d, autostart, profile.d, ld.so.preload. '
                      'C\'est là que se logent les portes dérobées qui '
                      'survivent au redémarrage.',
                  icon: Icons.rocket_launch_outlined,
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 20),
        _OptionsCard(
          options: _options,
          health: state.health,
          onChanged: (value) => setState(() => _options = value),
        ),
        const SizedBox(height: 24),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.icon(
            onPressed: canStart ? () => _start(state) : null,
            icon: const Icon(Icons.play_arrow),
            label: Text(
              _scanType == ScanTypes.path
                  ? 'Analyser ${_targets.length} cible'
                      '${_targets.length > 1 ? 's' : ''}'
                  : 'Lancer l\'analyse',
            ),
          ),
        ),
        if (!canStart)
          Padding(
            padding: const EdgeInsets.only(top: 10),
            child: Text(
              'Choisissez au moins un dossier ou un fichier.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
      ],
    );
  }

  Widget _typeChoice(String type, String label, IconData icon) {
    final selected = _scanType == type;
    return ChoiceChip(
      selected: selected,
      onSelected: (_) => setState(() => _scanType = type),
      avatar: Icon(icon, size: 18),
      label: Text(label),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
    );
  }
}

/// Options du scan. Les moteurs indisponibles sont désactivés et expliqués,
/// plutôt que proposés puis silencieusement ignorés.
class _OptionsCard extends StatelessWidget {
  const _OptionsCard({
    required this.options,
    required this.health,
    required this.onChanged,
  });

  final ScanOptions options;
  final BackendHealth? health;
  final ValueChanged<ScanOptions> onChanged;

  bool _engineAvailable(String name) =>
      health?.engines.any((e) => e.name == name && e.available) ?? true;

  String? _engineDetail(String name) => health?.engines
      .firstWhere(
        (e) => e.name == name,
        orElse: () => const EngineStatus(name: '', available: true),
      )
      .detail;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      title: 'Moteurs et options',
      icon: Icons.tune,
      child: Column(
        children: [
          _switch(
            context,
            'ClamAV',
            'Moteur de signatures open source',
            options.useClamav,
            _engineAvailable('clamav'),
            _engineDetail('clamav'),
            (v) => onChanged(options.copyWith(useClamav: v)),
          ),
          _switch(
            context,
            'Règles YARA',
            'Détection par motifs de code',
            options.useYara,
            _engineAvailable('yara'),
            _engineDetail('yara'),
            (v) => onChanged(options.copyWith(useYara: v)),
          ),
          _switch(
            context,
            'Empreintes locales',
            'Comparaison SHA256 à la base embarquée',
            options.useHashDb,
            true,
            null,
            (v) => onChanged(options.copyWith(useHashDb: v)),
          ),
          _switch(
            context,
            'Heuristiques',
            'Signaux de risque sans signature connue',
            options.useHeuristics,
            true,
            null,
            (v) => onChanged(options.copyWith(useHeuristics: v)),
          ),
          _switch(
            context,
            'VirusTotal',
            'Envoie les empreintes au service en ligne',
            options.useVirustotal,
            _engineAvailable('virustotal'),
            _engineDetail('virustotal'),
            (v) => onChanged(options.copyWith(useVirustotal: v)),
          ),
          const Divider(height: 24),
          _switch(
            context,
            'Fouiller les archives',
            'Extrait zip et tar pour analyser leur contenu',
            options.scanArchives,
            true,
            null,
            (v) => onChanged(options.copyWith(scanArchives: v)),
          ),
          _switch(
            context,
            'Suivre les liens symboliques',
            'Risque de parcourir deux fois les mêmes fichiers',
            options.followSymlinks,
            true,
            null,
            (v) => onChanged(options.copyWith(followSymlinks: v)),
          ),
          _switch(
            context,
            'Quarantaine automatique',
            'Isole les menaces sans confirmation',
            options.autoQuarantine,
            true,
            null,
            (v) => onChanged(options.copyWith(autoQuarantine: v)),
          ),
        ],
      ),
    );
  }

  Widget _switch(
    BuildContext context,
    String title,
    String subtitle,
    bool value,
    bool available,
    String? unavailableReason,
    ValueChanged<bool> onToggle,
  ) {
    final theme = Theme.of(context);
    return SwitchListTile(
      value: value && available,
      onChanged: available ? onToggle : null,
      dense: true,
      contentPadding: EdgeInsets.zero,
      title: Text(title, style: theme.textTheme.bodyMedium),
      subtitle: Text(
        available
            ? subtitle
            : (unavailableReason ?? 'Indisponible sur cette machine'),
        style: theme.textTheme.bodySmall?.copyWith(
          color: available
              ? theme.colorScheme.onSurfaceVariant
              : SeverityPalette.medium.withValues(alpha: 0.9),
        ),
      ),
    );
  }
}

/// Vue du scan en cours : progression, compteurs, menaces au fil de l'eau.
class _ScanRunningView extends StatelessWidget {
  const _ScanRunningView({required this.scan});

  final ActiveScan scan;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final progress = scan.progress;
    final percent = progress?.percent;
    final done = scan.finished;

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 0),
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      if (!done)
                        const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2.5),
                        )
                      else
                        Icon(
                          scan.status == ScanStatuses.cancelled
                              ? Icons.cancel_outlined
                              : Icons.check_circle_outline,
                          color: scan.status == ScanStatuses.cancelled
                              ? SeverityPalette.medium
                              : SeverityPalette.clean,
                        ),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              done
                                  ? ScanStatuses.label(scan.status)
                                  : progress?.phaseLabel ?? 'Préparation',
                              style: theme.textTheme.titleMedium,
                            ),
                            Text(
                              scan.targetLabel,
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ],
                        ),
                      ),
                      if (percent != null && !done)
                        Text(
                          '${percent.toStringAsFixed(1)} %',
                          style: theme.textTheme.headlineSmall?.copyWith(
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.primary,
                          ),
                        ),
                      const SizedBox(width: 16),
                      if (!done)
                        OutlinedButton.icon(
                          onPressed: state.cancelActiveScan,
                          icon: const Icon(Icons.stop, size: 18),
                          label: const Text('Arrêter'),
                        )
                      else
                        FilledButton.icon(
                          onPressed: state.clearActiveScan,
                          icon: const Icon(Icons.done, size: 18),
                          label: const Text('Terminer'),
                        ),
                    ],
                  ),
                  const SizedBox(height: 18),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(6),
                    child: LinearProgressIndicator(
                      value: done ? 1 : (percent == null ? null : percent / 100),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Wrap(
                    spacing: 24,
                    runSpacing: 10,
                    children: [
                      _counter(theme, 'Fichiers',
                          '${formatCount(progress?.filesScanned ?? 0)}'
                          '${progress?.filesTotal != null ? " / ${formatCount(progress!.filesTotal!)}" : ""}'),
                      _counter(theme, 'Volume',
                          formatBytes(progress?.bytesScanned ?? 0)),
                      _counter(theme, 'Menaces', '${scan.threats.length}',
                          accent: scan.threats.isEmpty
                              ? SeverityPalette.clean
                              : SeverityPalette.high),
                      _counter(theme, 'Erreurs', '${progress?.errors ?? 0}'),
                      _counter(theme, 'Durée',
                          formatSeconds(progress?.elapsedSeconds ?? 0)),
                    ],
                  ),
                  if (progress?.currentFile != null && !done) ...[
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Icon(Icons.chevron_right,
                            size: 16,
                            color: theme.colorScheme.onSurfaceVariant),
                        Expanded(
                          child: Text(
                            progress!.currentFile!,
                            style: theme.textTheme.bodySmall?.copyWith(
                              fontFamily: 'monospace',
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
        Expanded(
          child: scan.threats.isEmpty
              ? EmptyState(
                  icon: done ? Icons.verified_user_outlined : Icons.search,
                  title: done
                      ? 'Aucune menace détectée'
                      : 'Analyse en cours…',
                  message: done
                      ? 'Les fichiers analysés ne correspondent à aucune '
                          'signature connue et ne présentent pas de signal '
                          'de risque.'
                      : 'Les menaces apparaîtront ici dès qu\'elles seront '
                          'détectées.',
                )
              : ListView(
                  padding: const EdgeInsets.all(24),
                  children: [
                    Text(
                      '${scan.threats.length} menace'
                      '${scan.threats.length > 1 ? 's' : ''} détectée'
                      '${scan.threats.length > 1 ? 's' : ''}',
                      style: theme.textTheme.titleMedium,
                    ),
                    const SizedBox(height: 12),
                    for (final threat in scan.threats.reversed)
                      ThreatTile(
                        threat: threat,
                        onQuarantine: () => _quarantine(state, threat),
                      ),
                  ],
                ),
        ),
      ],
    );
  }

  Widget _counter(ThemeData theme, String label, String value,
      {Color? accent}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          label,
          style: theme.textTheme.labelSmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 2),
        Text(
          value,
          style: theme.textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
            color: accent,
          ),
        ),
      ],
    );
  }

  Future<void> _quarantine(AppState state, Threat threat) async {
    await state.quarantineThreat(threat);
  }
}

/// Résultat d'un scan terminé, consulté depuis l'historique.
class _ScanResultView extends StatelessWidget {
  const _ScanResultView({required this.result});

  final ScanResult result;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);

    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Row(
          children: [
            IconButton(
              icon: const Icon(Icons.arrow_back),
              tooltip: 'Retour',
              onPressed: state.clearSelectedScan,
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(ScanTypes.label(result.type),
                      style: theme.textTheme.titleLarge),
                  Text(
                    result.targets.join(', '),
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            SeverityChip(severity: result.maxSeverity),
          ],
        ),
        const SizedBox(height: 20),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Wrap(
              spacing: 28,
              runSpacing: 12,
              children: [
                DetailRow(
                    label: 'Statut', value: ScanStatuses.label(result.status)),
                DetailRow(
                    label: 'Fichiers analysés',
                    value: formatCount(result.filesScanned)),
                DetailRow(
                    label: 'Ignorés (trop gros)',
                    value: formatCount(result.filesSkipped)),
                DetailRow(
                    label: 'Volume', value: formatBytes(result.bytesScanned)),
                DetailRow(
                    label: 'Durée', value: formatDuration(result.duration)),
                DetailRow(
                    label: 'Démarré', value: formatDateTime(result.startedAt)),
                DetailRow(
                    label: 'Moteurs',
                    value: result.enginesUsed.isEmpty
                        ? '—'
                        : result.enginesUsed.join(', ')),
              ],
            ),
          ),
        ),
        if (result.errors.isNotEmpty) ...[
          const SizedBox(height: 16),
          SectionCard(
            title: '${result.errors.length} erreur(s) pendant le scan',
            icon: Icons.report_gmailerrorred_outlined,
            subtitle: 'Souvent des permissions insuffisantes.',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                for (final error in result.errors.take(10))
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Text(
                      error,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ],
        const SizedBox(height: 20),
        if (result.threats.isEmpty)
          EmptyState(
            icon: Icons.verified_user_outlined,
            title: 'Aucune menace',
            message: 'Ce scan n\'a rien trouvé.',
          )
        else ...[
          Text('Menaces détectées', style: theme.textTheme.titleMedium),
          const SizedBox(height: 12),
          for (final threat in result.threats)
            ThreatTile(
              threat: threat,
              onQuarantine: () => state.quarantineThreat(threat),
            ),
        ],
      ],
    );
  }
}
