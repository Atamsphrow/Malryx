import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import '../utils/formatters.dart';
import '../widgets/common.dart';

/// Réglages : protection, moteurs, VirusTotal, exclusions, apparence.
///
/// Chaque modification est envoyée immédiatement au backend (PUT
/// /api/settings), qui la persiste et recharge les moteurs concernés. Il n'y a
/// donc pas de bouton « Enregistrer » : l'état affiché est toujours celui du
/// backend.
class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final settings = state.settings;

    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        SectionCard(
          title: 'Protection',
          icon: Icons.shield_outlined,
          child: Column(
            children: [
              _Toggle(
                title: 'Analyse automatique des médias amovibles',
                subtitle: 'Lance un scan dès qu\'une clé USB est branchée.',
                value: settings['autoscan_removable'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('autoscan_removable', v),
              ),
              _Toggle(
                title: 'Protection en temps réel',
                subtitle: 'Surveillance continue des fichiers créés ou '
                    'modifiés dans les dossiers sensibles et d\'entrée.',
                value: settings['realtime_protection'] as bool? ?? false,
                enabled: true,
                onChanged: (v) => state.updateSetting('realtime_protection', v),
              ),
              _Toggle(
                title: 'Quarantaine automatique',
                subtitle: 'Isole les menaces détectées sans demander '
                    'confirmation. Prudence : un faux positif isolera un '
                    'fichier légitime.',
                value: settings['auto_quarantine'] as bool? ?? false,
                onChanged: (v) => state.updateSetting('auto_quarantine', v),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SectionCard(
          title: 'Moteurs de détection',
          icon: Icons.memory_outlined,
          subtitle: 'Désactiver un moteur accélère les scans mais réduit la '
              'couverture.',
          child: Column(
            children: [
              _Toggle(
                title: 'ClamAV',
                subtitle: 'Moteur de signatures open source.',
                value: settings['clamav_enabled'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('clamav_enabled', v),
              ),
              _Toggle(
                title: 'Règles YARA',
                subtitle: 'Détection par motifs. Les règles ajoutées dans '
                    '~/.local/share/malryx/yara/ sont chargées au démarrage.',
                value: settings['yara_enabled'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('yara_enabled', v),
              ),
              _Toggle(
                title: 'Heuristiques',
                subtitle: 'Signaux de risque sans signature connue.',
                value: settings['heuristics_enabled'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('heuristics_enabled', v),
              ),
              _Toggle(
                title: 'Vérification CVE (OSV)',
                subtitle: 'Recoupe les paquets installés avec OSV.dev. '
                    'Opt-in : envoie les noms et versions des paquets à un '
                    'service cloud, désactivé par défaut.',
                value: settings['cve_enabled'] as bool? ?? false,
                onChanged: (v) => state.updateSetting('cve_enabled', v),
              ),
              _Toggle(
                title: 'Fouiller les archives',
                subtitle: 'Extrait zip et tar pour analyser leur contenu.',
                value: settings['scan_archives'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('scan_archives', v),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        _VirusTotalCard(),
        const SizedBox(height: 16),
        _ExclusionsCard(),
        const SizedBox(height: 16),
        _AppearanceCard(),
        const SizedBox(height: 16),
        _AboutCard(),
      ],
    );
  }
}

class _Toggle extends StatelessWidget {
  const _Toggle({
    required this.title,
    required this.subtitle,
    required this.value,
    required this.onChanged,
    this.enabled = true,
  });

  final String title;
  final String subtitle;
  final bool value;
  final ValueChanged<bool> onChanged;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SwitchListTile(
      value: value,
      onChanged: enabled ? onChanged : null,
      contentPadding: EdgeInsets.zero,
      title: Text(title, style: theme.textTheme.bodyLarge),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 2),
        child: Text(
          subtitle,
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
      ),
      isThreeLine: subtitle.length > 70,
    );
  }
}

/// VirusTotal : opt-in explicite, avec la conséquence énoncée clairement.
class _VirusTotalCard extends StatefulWidget {
  @override
  State<_VirusTotalCard> createState() => _VirusTotalCardState();
}

class _VirusTotalCardState extends State<_VirusTotalCard> {
  final _keyController = TextEditingController();
  bool _obscure = true;

  @override
  void dispose() {
    _keyController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final enabled = state.settings['virustotal_enabled'] as bool? ?? false;
    final keySet = state.settings['virustotal_key_set'] as bool? ?? false;

    return SectionCard(
      title: 'VirusTotal',
      icon: Icons.cloud_outlined,
      subtitle: 'Vérification des empreintes auprès d\'un service tiers.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          NoticeBanner(
            message: 'Interroger VirusTotal revient à révéler à un tiers '
                'qu\'un fichier précis existe sur cette machine. Seules des '
                'empreintes SHA256 sont envoyées, jamais le contenu des '
                'fichiers. Désactivé par défaut.',
            icon: Icons.privacy_tip_outlined,
          ),
          const SizedBox(height: 16),
          _Toggle(
            title: 'Activer VirusTotal',
            subtitle: keySet
                ? 'Une clé API est enregistrée.'
                : 'Renseignez une clé API pour pouvoir l\'activer.',
            value: enabled,
            enabled: keySet,
            onChanged: (v) => state.updateSetting('virustotal_enabled', v),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _keyController,
                  obscureText: _obscure,
                  decoration: InputDecoration(
                    labelText: 'Clé API',
                    hintText: keySet
                        ? 'Une clé est déjà enregistrée'
                        : 'Collez votre clé VirusTotal',
                    suffixIcon: IconButton(
                      icon: Icon(_obscure
                          ? Icons.visibility_outlined
                          : Icons.visibility_off_outlined),
                      onPressed: () => setState(() => _obscure = !_obscure),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              FilledButton(
                onPressed: _keyController.text.trim().isEmpty
                    ? null
                    : () async {
                        await state.updateSetting(
                            'virustotal_api_key', _keyController.text.trim());
                        _keyController.clear();
                        setState(() {});
                      },
                child: const Text('Enregistrer'),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'La clé est stockée en clair dans '
            '~/.config/malryx/settings.json, avec des permissions 600. '
            'Elle n\'est jamais renvoyée à l\'interface.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Quota de l\'API publique : 4 requêtes par minute. Les fichiers '
            'déjà identifiés par un moteur local ne sont pas envoyés, et les '
            'verdicts sont mis en cache 7 jours.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}

class _ExclusionsCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final excluded =
        (state.settings['excluded_paths'] as List?)?.cast<String>() ?? const [];
    final maxSize = state.settings['max_file_size_mb'] as int? ?? 256;

    return SectionCard(
      title: 'Limites et exclusions',
      icon: Icons.filter_alt_outlined,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Taille maximale par fichier : $maxSize Mio',
              style: theme.textTheme.bodyMedium),
          Slider(
            value: maxSize.toDouble().clamp(16, 2048),
            min: 16,
            max: 2048,
            divisions: 16,
            label: '$maxSize Mio',
            onChanged: (value) {},
            onChangeEnd: (value) =>
                state.updateSetting('max_file_size_mb', value.round()),
          ),
          Text(
            'Au-delà de cette taille, les fichiers sont comptés comme ignorés. '
            'Les gros fichiers sont rarement porteurs de code malveillant et '
            'ralentissent beaucoup le scan.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const Divider(height: 28),
          Text('Chemins exclus (${excluded.length})',
              style: theme.textTheme.labelLarge),
          const SizedBox(height: 8),
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: [
              for (final path in excluded)
                Chip(
                  label: Text(path, style: const TextStyle(fontSize: 11)),
                  visualDensity: VisualDensity.compact,
                ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Les pseudo-systèmes de fichiers (/proc, /sys, /dev) sont exclus '
            'd\'office : les parcourir n\'a pas de sens et peut boucler '
            'indéfiniment. Le dossier de quarantaine l\'est aussi, sinon le '
            'scanner se détecterait lui-même en boucle.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}

class _AppearanceCard extends StatelessWidget {
  static const List<({String name, Color color})> _seeds = [
    (name: 'Cyan', color: Color(0xFF00D9FF)),
    (name: 'Violet', color: Color(0xFF8B5CF6)),
    (name: 'Émeraude', color: Color(0xFF10B981)),
    (name: 'Ambre', color: Color(0xFFF59E0B)),
    (name: 'Rose', color: Color(0xFFEC4899)),
    (name: 'Indigo', color: Color(0xFF6366F1)),
  ];

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final current = state.settings['accent_color'] as String? ?? '#FF00D9FF';

    return SectionCard(
      title: 'Apparence',
      icon: Icons.palette_outlined,
      subtitle: 'Mode sombre uniquement. La palette entière est générée à '
          'partir de la couleur d\'accent.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              for (final seed in _seeds)
                _SeedSwatch(
                  name: seed.name,
                  color: seed.color,
                  selected: _hex(seed.color).toLowerCase() ==
                      current.toLowerCase(),
                  onTap: () =>
                      state.updateSetting('accent_color', _hex(seed.color)),
                ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            'Le thème n\'emprunte rien au thème système : une mise à jour de '
            'GNOME ou de libadwaita ne peut pas altérer l\'apparence de '
            'l\'application.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  static String _hex(Color color) {
    final value = color.toARGB32().toRadixString(16).padLeft(8, '0');
    return '#${value.toUpperCase()}';
  }
}

class _SeedSwatch extends StatelessWidget {
  const _SeedSwatch({
    required this.name,
    required this.color,
    required this.selected,
    required this.onTap,
  });

  final String name;
  final Color color;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: selected ? color : theme.colorScheme.outlineVariant,
            width: selected ? 2 : 1,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 18,
              height: 18,
              decoration: BoxDecoration(color: color, shape: BoxShape.circle),
            ),
            const SizedBox(width: 10),
            Text(name, style: theme.textTheme.bodyMedium),
            if (selected) ...[
              const SizedBox(width: 8),
              Icon(Icons.check, size: 16, color: color),
            ],
          ],
        ),
      ),
    );
  }
}

class _AboutCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final health = state.health;

    return SectionCard(
      title: 'À propos',
      icon: Icons.info_outline,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const DetailRow(label: 'Application', value: 'Malryx'),
          const DetailRow(
              label: 'Identifiant', value: 'com.atamsphrow.malryx'),
          DetailRow(label: 'Backend', value: health?.version ?? '—'),
          DetailRow(label: 'Plateforme', value: health?.platform ?? '—'),
          DetailRow(
            label: 'Privilèges',
            value: health == null
                ? '—'
                : (health.root
                    ? 'root (accès complet au système de fichiers)'
                    : 'utilisateur (certains fichiers système seront illisibles)'),
          ),
          DetailRow(
            label: 'Empreintes locales',
            value: formatCount(state.stats.localSignatures),
          ),
          DetailRow(
            label: 'Flux temps réel',
            value: state.wsConnected ? 'connecté' : 'déconnecté',
          ),
        ],
      ),
    );
  }
}
