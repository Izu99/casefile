// Renders the main screens to PNG (no device needed) against a saved real scan:
//   CASEFILE_SCAN=<scan.json> flutter test --update-goldens test/screens_test.dart
// Also fails on any overflow at the window sizes the app ships on.
import 'dart:convert';
import 'dart:io';

import 'package:casefile_app/engine.dart';
import 'package:casefile_app/main.dart';
import 'package:casefile_app/tokens.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeEngine implements Engine {
  FakeEngine(this.scan);
  final Json scan;
  @override
  String get base => '';
  @override
  void stop() {}
  @override
  Future<dynamic> get(String path) async {
    if (path == 'checklist')
      return List.filled((scan['checks'] as List).length, {});
    if (path == 'tools') {
      const v = {
        'semgrep': '1.172.0',
        'gitleaks': '8.30.1',
        'osv-scanner': '2.7.1',
        'nuclei': '3.11.1',
        'zap': '2.17.0',
        'ssh-audit': '3.9.0',
        'lynis': '3.1.7',
        'claude': '2.1.0',
      };
      return {
        'tools': {for (final k in v.keys) k: true},
        'versions': v,
        'rules_date': '2026-11-11',
        'nuclei_templates': 14104,
      };
    }
    if (path == 'projects') {
      return [
        {
          'path': scan['path'],
          'name': scan['project'],
          'last_scan': scan['when'],
          'score': scan['score'],
          'open': scan['open'],
        },
        {
          'path': '/x/acweb',
          'name': 'acweb',
          'last_scan': '2026-11-10 18:02',
          'score': 81,
          'open': 12,
        },
      ];
    }
    if (path.startsWith('report')) {
      return {
        'meta': {
          'path': scan['path'],
          'name': scan['project'],
          'url': '',
          'ssh': '',
        },
        'report': scan,
      };
    }
    return {};
  }

  @override
  Future<dynamic> post(String path, [Json body = const {}]) async => {};
  @override
  Future<Json> poll(Json job, [void Function(Json)? onTick]) async => job;
  @override
  dynamic noSuchMethod(Invocation i) => super.noSuchMethod(i);
}

Future<void> loadFonts() async {
  for (final (family, files) in [
    ('BowlbyOne', ['BowlbyOne-Regular.ttf']),
    ('CourierPrime', ['CourierPrime-Regular.ttf', 'CourierPrime-Bold.ttf']),
    (
      'Supreme',
      ['Supreme-Regular.otf', 'Supreme-Medium.otf', 'Supreme-Bold.otf'],
    ),
    ('Phosphor', ['Phosphor.ttf']),
  ]) {
    final l = FontLoader(family);
    for (final f in files) {
      l.addFont(
        Future.value(
          ByteData.sublistView(File('assets/fonts/$f').readAsBytesSync()),
        ),
      );
    }
    await l.load();
  }
}

void main() {
  final scanFile = Platform.environment['CASEFILE_SCAN'];
  if (scanFile == null) return;
  final scan = Json.from(jsonDecode(File(scanFile).readAsStringSync()));

  setUpAll(loadFonts);

  for (final size in [const Size(1440, 900), const Size(1024, 700)]) {
    testWidgets('screens at ${size.width.toInt()}', (t) async {
      t.view.physicalSize = size;
      t.view.devicePixelRatio = 1;
      addTearDown(t.view.reset);
      await t.pumpWidget(
        MaterialApp(
          theme: buildTheme(),
          debugShowCheckedModeBanner: false,
          home: Home(startEngine: () async => FakeEngine(scan)),
        ),
      );
      await t.pumpAndSettle();
      final w = size.width.toInt();
      await expectLater(
        find.byType(Home),
        matchesGoldenFile('goldens/start-$w.png'),
      );

      await t.tap(find.text(scan['project']).first);
      await t.pumpAndSettle();
      await expectLater(
        find.byType(Home),
        matchesGoldenFile('goldens/project-$w.png'),
      );

      // open the first failing checklist item, scroll to it
      final fig = find.textContaining('FOUND').first;
      await t.ensureVisible(fig);
      await t.tap(fig);
      await t.pumpAndSettle();
      await expectLater(
        find.byType(Home),
        matchesGoldenFile('goldens/check-open-$w.png'),
      );

      await t.ensureVisible(find.textContaining('All findings'));
      await t.tap(find.textContaining('All findings'));
      await t.pumpAndSettle();
      await expectLater(
        find.byType(Home),
        matchesGoldenFile('goldens/findings-$w.png'),
      );

      final routesTab = find.textContaining('Routes (');
      if (routesTab.evaluate().isNotEmpty) {
        await t.ensureVisible(routesTab);
        await t.tap(routesTab);
        await t.pumpAndSettle();
        await expectLater(
          find.byType(Home),
          matchesGoldenFile('goldens/routes-$w.png'),
        );
      }
    });
  }
}
