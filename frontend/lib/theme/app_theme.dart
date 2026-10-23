import 'package:flutter/material.dart';

/// Thème de Malryx : Material 3, mode sombre exclusivement.
///
/// La palette est générée par `ColorScheme.fromSeed()` à partir d'une couleur
/// d'accent, donc entièrement calculée côté Flutter. Aucune dépendance au thème
/// système : une mise à jour de GNOME ou de libadwaita ne peut pas casser
/// l'apparence de l'application.
class MalryxTheme {
  MalryxTheme._();

  /// Couleur d'accent par défaut. Modifiable dans les réglages, ce qui
  /// régénère toute la palette de façon cohérente.
  static const Color defaultSeed = Color(0xFF00D9FF);

  /// Rayon d'arrondi commun. Material 3 emploie des formes très arrondies ;
  /// on reste un peu plus sobre pour une application de bureau dense.
  static const double radius = 16;

  static ThemeData dark([Color seed = defaultSeed]) {
    final scheme = ColorScheme.fromSeed(
      seedColor: seed,
      brightness: Brightness.dark,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: scheme.surface,
      visualDensity: VisualDensity.compact,
      splashFactory: InkSparkle.splashFactory,

      appBarTheme: AppBarTheme(
        backgroundColor: scheme.surface,
        surfaceTintColor: scheme.surfaceTint,
        elevation: 0,
        scrolledUnderElevation: 3,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: scheme.onSurface,
          fontSize: 20,
          fontWeight: FontWeight.w600,
        ),
      ),

      cardTheme: CardThemeData(
        color: scheme.surfaceContainerLow,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(radius),
          side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.5)),
        ),
      ),

      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: scheme.surfaceContainerLowest,
        indicatorColor: scheme.secondaryContainer,
        selectedIconTheme: IconThemeData(color: scheme.onSecondaryContainer),
        unselectedIconTheme: IconThemeData(color: scheme.onSurfaceVariant),
        selectedLabelTextStyle: TextStyle(
          color: scheme.onSurface,
          fontWeight: FontWeight.w600,
          fontSize: 12,
        ),
        unselectedLabelTextStyle: TextStyle(
          color: scheme.onSurfaceVariant,
          fontSize: 12,
        ),
      ),

      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),

      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      ),

      progressIndicatorTheme: ProgressIndicatorThemeData(
        linearTrackColor: scheme.surfaceContainerHighest,
        linearMinHeight: 8,
      ),

      dividerTheme: DividerThemeData(
        color: scheme.outlineVariant.withValues(alpha: 0.4),
        space: 1,
        thickness: 1,
      ),

      listTileTheme: ListTileThemeData(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        iconColor: scheme.onSurfaceVariant,
      ),

      snackBarTheme: SnackBarThemeData(
        backgroundColor: scheme.inverseSurface,
        contentTextStyle: TextStyle(color: scheme.onInverseSurface),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),

      chipTheme: ChipThemeData(
        side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.6)),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),

      tooltipTheme: TooltipThemeData(
        decoration: BoxDecoration(
          color: scheme.inverseSurface,
          borderRadius: BorderRadius.circular(8),
        ),
        textStyle: TextStyle(color: scheme.onInverseSurface, fontSize: 12),
      ),
    );
  }
}

/// Couleurs sémantiques de gravité.
///
/// Elles ne viennent pas du `ColorScheme` : un rouge de danger doit rester
/// rouge même si l'utilisateur choisit une couleur d'accent rouge. Elles sont
/// choisies pour rester lisibles sur fond sombre.
class SeverityPalette {
  SeverityPalette._();

  static const Color clean = Color(0xFF4ADE80);
  static const Color low = Color(0xFF60A5FA);
  static const Color medium = Color(0xFFFBBF24);
  static const Color high = Color(0xFFFB923C);
  static const Color critical = Color(0xFFF87171);

  static Color of(String severity) => switch (severity) {
        'clean' => clean,
        'low' => low,
        'medium' => medium,
        'high' => high,
        'critical' => critical,
        _ => medium,
      };

  static IconData iconOf(String severity) => switch (severity) {
        'clean' => Icons.check_circle_outline,
        'low' => Icons.info_outline,
        'medium' => Icons.warning_amber_outlined,
        'high' => Icons.error_outline,
        'critical' => Icons.dangerous_outlined,
        _ => Icons.help_outline,
      };

  /// Libellé français affiché dans l'interface.
  static String labelOf(String severity) => switch (severity) {
        'clean' => 'Sain',
        'low' => 'Faible',
        'medium' => 'Moyen',
        'high' => 'Élevé',
        'critical' => 'Critique',
        _ => severity,
      };
}
