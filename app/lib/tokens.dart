// Casefile tokens - declassified dossier (see ../DESIGN.md).
// Widgets use only these: no raw hex or one-off radii elsewhere.
import 'package:flutter/material.dart';

class C {
  static const manila = Color(0xFFD8B97A);
  static const manilaDeep = Color(0xFFC9A660);
  static const paper = Color(0xFFF4EFE4);
  static const sheet = Color(0xFFFBF8F1);
  static const ink = Color(0xFF161412);
  static const ink2 = Color(0xFF3A352E);
  static const muted = Color(0xFF5E574C);
  static const faint = Color(0xFF9C9384); // "not used here" dots only - never text
  static const rule = Color(0xFFD9CFBD);
  static const stamp = Color(0xFFC22A1E);
  static const amber = Color(0xFFE39B1B);
  static const ok = Color(0xFF1F5D3A);
  static const code = Color(0xFFEDE6D6);
}

class F {
  static const display = 'BowlbyOne';
  static const ui = 'Supreme';
  static const type = 'CourierPrime';
}

class R {
  static const sm = 2.0, md = 8.0, tab = 10.0, pill = 999.0;
}

class S {
  static const s1 = 4.0,
      s2 = 8.0,
      s3 = 12.0,
      s4 = 16.0,
      s5 = 24.0,
      s6 = 36.0,
      s7 = 56.0;
}

class T {
  static TextStyle display(double size, {Color color = C.ink}) => TextStyle(
    fontFamily: F.display,
    fontSize: size,
    height: 1,
    color: color,
    letterSpacing: -0.5,
  );
  static TextStyle ui(
    double size, {
    FontWeight w = FontWeight.w400,
    Color color = C.ink,
    double height = 1.45,
  }) => TextStyle(
    fontFamily: F.ui,
    fontSize: size,
    fontWeight: w,
    color: color,
    height: height,
  );
  static TextStyle type(
    double size, {
    Color color = C.ink2,
    FontWeight w = FontWeight.w400,
    double height = 1.45,
  }) => TextStyle(
    fontFamily: F.type,
    fontSize: size,
    color: color,
    fontWeight: w,
    height: height,
  );
  static TextStyle label({Color color = C.ink2}) => TextStyle(
    fontFamily: F.ui,
    fontSize: 11,
    fontWeight: FontWeight.w700,
    letterSpacing: 1.4,
    color: color,
    height: 1,
  );
}

const severities = ['critical', 'high', 'medium', 'low'];

Color sevFill(String s) => switch (s) {
  'critical' => C.stamp,
  'high' => C.ink,
  'medium' => C.amber,
  _ => Colors.transparent,
};

Color sevText(String s) => switch (s) {
  'critical' => Colors.white,
  'high' => C.paper,
  _ => C.ink,
};

ThemeData buildTheme() => ThemeData(
  useMaterial3: true,
  fontFamily: F.ui,
  scaffoldBackgroundColor: C.paper,
  colorScheme: const ColorScheme.light(
    primary: C.ink,
    onPrimary: C.paper,
    surface: C.paper,
    onSurface: C.ink,
    error: C.stamp,
  ),
  checkboxTheme: CheckboxThemeData(
    fillColor: WidgetStateProperty.resolveWith(
      (s) => s.contains(WidgetState.selected) ? C.ink : Colors.transparent,
    ),
    side: const BorderSide(color: C.ink, width: 1.5),
    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(R.sm)),
  ),
  scrollbarTheme: ScrollbarThemeData(
    thumbVisibility: WidgetStateProperty.all(true),
    thickness: WidgetStateProperty.all(10),
    thumbColor: WidgetStateProperty.all(C.ink.withValues(alpha: .35)),
    radius: const Radius.circular(R.pill),
  ),
  tooltipTheme: const TooltipThemeData(
    decoration: BoxDecoration(
      color: C.ink,
      borderRadius: BorderRadius.all(Radius.circular(R.sm)),
    ),
    textStyle: TextStyle(fontFamily: F.ui, fontSize: 12, color: C.paper),
  ),
  textSelectionTheme: TextSelectionThemeData(
    cursorColor: C.ink,
    selectionColor: C.manila.withValues(alpha: .7),
  ),
);
