import 'package:flutter/material.dart';

import '../models/threat.dart';
import '../theme/app_theme.dart';
import '../utils/formatters.dart';
import 'common.dart';

/// Ligne de menace, dépliable pour montrer le détail du verdict.
///
/// Le détail est important : une détection heuristique n'est pas une preuve, et
/// l'utilisateur doit pouvoir juger avant de supprimer un fichier. On affiche
/// donc les raisons du verdict, pas seulement un nom de menace.
class ThreatTile extends StatelessWidget {
  const ThreatTile({
    super.key,
    required this.threat,
    this.onQuarantine,
    this.dense = false,
  });

  final Threat threat;
  final Future<void> Function()? onQuarantine;
  final bool dense;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = SeverityPalette.of(threat.severity);

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHigh.withValues(alpha: 0.4),
        borderRadius: BorderRadius.circular(12),
        border: Border(
          left: BorderSide(color: color, width: 3),
          top: BorderSide(color: theme.colorScheme.outlineVariant
              .withValues(alpha: 0.3)),
          right: BorderSide(color: theme.colorScheme.outlineVariant
              .withValues(alpha: 0.3)),
          bottom: BorderSide(color: theme.colorScheme.outlineVariant
              .withValues(alpha: 0.3)),
        ),
      ),
      child: Theme(
        // Retire les séparateurs par défaut de l'ExpansionTile.
        data: theme.copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: EdgeInsets.symmetric(
              horizontal: 14, vertical: dense ? 0 : 4),
          childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
          shape: const Border(),
          collapsedShape: const Border(),
          leading: Icon(SeverityPalette.iconOf(threat.severity),
              color: color, size: 22),
          title: Text(
            threat.name,
            style: theme.textTheme.bodyLarge?.copyWith(
              fontWeight: FontWeight.w500,
            ),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          subtitle: Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Text(
              threat.archiveMember != null
                  ? '${threat.fileName} › ${threat.archiveMember}'
                  : shortenPath(threat.path, maxLength: 80),
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontFamily: 'monospace',
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (threat.quarantined)
                Tooltip(
                  message: 'Isolé en quarantaine',
                  child: Icon(Icons.lock_outline,
                      size: 18, color: SeverityPalette.clean),
                )
              else
                SeverityChip(severity: threat.severity, compact: true),
              const SizedBox(width: 8),
              const Icon(Icons.expand_more, size: 20),
            ],
          ),
          children: [_details(context)],
        ),
      ),
    );
  }

  Widget _details(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Divider(height: 1),
        const SizedBox(height: 10),
        DetailRow(label: 'Chemin', value: threat.path, selectable: true),
        if (threat.archiveMember != null)
          DetailRow(
            label: 'Dans l\'archive',
            value: threat.archiveMember!,
            selectable: true,
          ),
        DetailRow(
          label: 'Détecté par',
          value: detectionSourceLabel(threat.source),
        ),
        DetailRow(
          label: 'Gravité',
          value: SeverityPalette.labelOf(threat.severity),
        ),
        if (threat.size != null)
          DetailRow(label: 'Taille', value: formatBytes(threat.size)),
        if (threat.sha256 != null)
          DetailRow(
            label: 'SHA256',
            value: threat.sha256!,
            selectable: true,
            monospace: true,
          ),
        if (threat.virusTotalRatio != null)
          DetailRow(
            label: 'Moteurs VirusTotal',
            value: '${threat.virusTotalRatio} l\'identifient comme malveillant',
          ),
        DetailRow(label: 'Détecté à', value: formatTime(threat.detectedAt)),

        if (threat.reasons.isNotEmpty) ...[
          const SizedBox(height: 12),
          Text('Signaux relevés', style: theme.textTheme.labelLarge),
          const SizedBox(height: 6),
          for (final reason in threat.reasons)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 6, right: 8),
                    child: Icon(Icons.circle,
                        size: 5, color: theme.colorScheme.onSurfaceVariant),
                  ),
                  Expanded(
                    child: Text(reason, style: theme.textTheme.bodySmall),
                  ),
                ],
              ),
            ),
        ],

        if (threat.source == 'heuristic') ...[
          const SizedBox(height: 12),
          NoticeBanner(
            message: 'Détection heuristique : ce sont des signaux de risque, '
                'pas une signature connue. Vérifiez le fichier avant de le '
                'supprimer.',
            icon: Icons.lightbulb_outline,
          ),
        ],

        if (onQuarantine != null && !threat.quarantined) ...[
          const SizedBox(height: 14),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
              onPressed: onQuarantine,
              icon: const Icon(Icons.shield_outlined, size: 18),
              label: const Text('Mettre en quarantaine'),
            ),
          ),
        ],
      ],
    );
  }
}
