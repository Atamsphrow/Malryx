import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/quarantine_entry.dart';
import '../models/threat.dart';
import '../state/app_state.dart';
import '../theme/app_theme.dart';
import '../utils/formatters.dart';
import '../widgets/common.dart';

/// Quarantaine : fichiers isolés, restauration, suppression définitive.
class QuarantineScreen extends StatelessWidget {
  const QuarantineScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final entries = state.quarantine;

    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Quarantaine', style: theme.textTheme.titleLarge),
                  const SizedBox(height: 4),
                  Text(
                    'Les fichiers isolés sont neutralisés sur le disque : ils ne '
                    'peuvent plus être exécutés, mais rien n\'est détruit.',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
            OutlinedButton.icon(
              onPressed: state.refreshQuarantine,
              icon: const Icon(Icons.refresh, size: 18),
              label: const Text('Rafraîchir'),
            ),
          ],
        ),
        const SizedBox(height: 20),
        if (entries.isEmpty)
          const EmptyState(
            icon: Icons.lock_open_outlined,
            title: 'Quarantaine vide',
            message: 'Aucun fichier n\'est actuellement isolé.',
          )
        else
          for (final entry in entries)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: _QuarantineCard(entry: entry),
            ),
      ],
    );
  }
}

class _QuarantineCard extends StatelessWidget {
  const _QuarantineCard({required this.entry});

  final QuarantineEntry entry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = context.read<AppState>();
    final color = SeverityPalette.of(entry.severity);

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Container(
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.14),
                    borderRadius: BorderRadius.circular(11),
                  ),
                  child: Icon(Icons.lock_outline, color: color, size: 21),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(entry.fileName,
                          style: theme.textTheme.titleMedium),
                      const SizedBox(height: 2),
                      Text(
                        entry.threatName ??
                            'Isolé manuellement, aucune signature associée',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                SeverityChip(severity: entry.severity),
              ],
            ),
            const SizedBox(height: 16),
            DetailRow(
              label: 'Emplacement d\'origine',
              value: entry.originalPath,
              selectable: true,
              monospace: true,
            ),
            DetailRow(label: 'Taille', value: formatBytes(entry.size)),
            DetailRow(
              label: 'SHA256',
              value: entry.sha256,
              selectable: true,
              monospace: true,
            ),
            if (entry.source != null)
              DetailRow(
                label: 'Détecté par',
                value: detectionSourceLabel(entry.source!),
              ),
            DetailRow(
              label: 'Isolé le',
              value: '${formatDateTime(entry.quarantinedAt)} '
                  '(${formatRelative(entry.quarantinedAt)})',
            ),
            if (entry.originalMode != null)
              DetailRow(
                label: 'Permissions d\'origine',
                value: formatMode(entry.originalMode),
                monospace: true,
              ),
            const SizedBox(height: 16),
            Row(
              children: [
                OutlinedButton.icon(
                  onPressed: () => _confirmRestore(context, state),
                  icon: const Icon(Icons.restore, size: 18),
                  label: const Text('Restaurer'),
                ),
                const SizedBox(width: 12),
                OutlinedButton.icon(
                  onPressed: () => _confirmDelete(context, state),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: SeverityPalette.critical,
                    side: BorderSide(
                      color: SeverityPalette.critical.withValues(alpha: 0.5),
                    ),
                  ),
                  icon: const Icon(Icons.delete_forever_outlined, size: 18),
                  label: const Text('Supprimer définitivement'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _confirmRestore(BuildContext context, AppState state) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Restaurer ce fichier ?'),
        content: Text(
          'Le fichier sera remis à son emplacement d\'origine :\n'
          '${entry.originalPath}\n\n'
          'S\'il est réellement malveillant, il redeviendra actif. '
          'Son empreinte est vérifiée avant restauration.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Annuler'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Restaurer'),
          ),
        ],
      ),
    );
    if (confirmed == true) await state.restoreQuarantine(entry.id);
  }

  Future<void> _confirmDelete(BuildContext context, AppState state) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        icon: Icon(Icons.warning_amber_rounded,
            color: SeverityPalette.critical, size: 32),
        title: const Text('Suppression définitive'),
        content: Text(
          '${entry.fileName} sera effacé du disque. Cette action est '
          'irréversible : le fichier ne pourra plus être restauré, même s\'il '
          's\'agissait d\'un faux positif.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Annuler'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: SeverityPalette.critical,
            ),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Supprimer'),
          ),
        ],
      ),
    );
    if (confirmed == true) await state.deleteQuarantine(entry.id);
  }
}
