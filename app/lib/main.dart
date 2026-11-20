// Casefile - pick a project, run every security check one by one, keep the case file.
import 'package:flutter/material.dart';

import 'engine.dart';
import 'icons.dart';
import 'report.dart';
import 'tokens.dart';
import 'widgets.dart';

void main() => runApp(const CasefileApp());

class CasefileApp extends StatelessWidget {
  const CasefileApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Casefile',
    debugShowCheckedModeBanner: false,
    theme: buildTheme(),
    home: const Home(),
  );
}

enum View { start, project, web, server }

class Home extends StatefulWidget {
  const Home({super.key, this.startEngine = Engine.start});
  final Future<Engine> Function()
  startEngine; // swapped for a fake in the screen tests
  @override
  State<Home> createState() => _HomeState();
}

class _HomeState extends State<Home> {
  Engine? engine;
  String? bootError;
  View view = View.start;
  List<Json> projects = [];
  Json toolInfo = {};
  int checkCount = 56;
  final mainScroll = ScrollController();

  // project
  String? path;
  Json? meta, report;
  Json? job; // running scan
  bool land = false, exporting = false;
  bool optClaude = false,
      optNuclei = true,
      optZap = false,
      optLynis = false,
      optTests = false;
  final url = TextEditingController(), ssh = TextEditingController();

  // live checks
  final liveTarget = {
    View.web: TextEditingController(),
    View.server: TextEditingController(),
  };
  final liveReport = <View, Json?>{};
  final liveJob = <View, Json?>{};
  bool liveNuclei = true,
      liveZap = false,
      liveActive = false,
      liveLynis = false;

  // scanner updates
  Json? updateJob;

  Map<String, dynamic> get tools =>
      Map<String, dynamic>.from(toolInfo['tools'] ?? {});
  Map<String, dynamic> get versions =>
      Map<String, dynamic>.from(toolInfo['versions'] ?? {});

  @override
  void initState() {
    super.initState();
    widget
        .startEngine()
        .then((e) async {
          engine = e;
          checkCount = (await e.get('checklist') as List).length;
          await loadRail();
        })
        .catchError((Object e) {
          setState(() => bootError = '$e');
        });
  }

  @override
  void dispose() {
    engine?.stop();
    super.dispose();
  }

  Future<void> loadRail() async {
    final p = await engine!.get('projects') as List;
    final t = await engine!.get('tools');
    setState(() {
      projects = p.map((e) => Json.from(e)).toList();
      toolInfo = Json.from(t);
    });
  }

  void toast(String m) => ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(m, style: T.ui(13.5, color: C.paper)),
      backgroundColor: C.ink,
      behavior: SnackBarBehavior.floating,
      width: 620,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(R.pill),
      ),
    ),
  );

  Future<void> pickFolder() async {
    final res = await engine!.post('pick');
    final p = (res['path'] ?? '') as String;
    if (p.isNotEmpty) openProject(p, scanIfNew: true);
  }

  Future<void> openProject(String p, {bool scanIfNew = false}) async {
    final res = await engine!.get('report?path=${Uri.encodeComponent(p)}');
    setState(() {
      view = View.project;
      path = p;
      meta = Json.from(res['meta']);
      report = res['report'] == null ? null : Json.from(res['report']);
      url.text = meta!['url'] ?? '';
      ssh.text = meta!['ssh'] ?? '';
      land = false;
      job = null;
    });
    loadRail();
    if (report == null && scanIfNew) scan();
  }

  Future<void> saveTargets() async {
    meta = Json.from(
      await engine!.post('meta', {
        'path': path,
        'url': url.text.trim(),
        'ssh': ssh.text.trim(),
      }),
    );
  }

  Future<void> scan() async {
    await saveTargets();
    final scanning = path;
    try {
      var j = Json.from(
        await engine!.post('scan', {
          'path': path,
          'claude': optClaude,
          'nuclei': optNuclei,
          'zap': optZap,
          'lynis': optLynis,
          'tests': optTests,
        }),
      );
      setState(() => job = j);
      j = await engine!.poll(j, (v) {
        if (mounted && path == scanning) setState(() => job = v);
      });
      if (path != scanning) return;
      if (j['state'] == 'done') {
        final res = await engine!.get(
          'report?path=${Uri.encodeComponent(path!)}',
        );
        setState(() {
          report = Json.from(j['result']);
          meta = Json.from(res['meta']);
          job = null;
          land = true;
        });
        loadRail();
      } else {
        setState(() => job = null);
        toast('Scan failed: ${j['error']}');
      }
    } catch (e) {
      setState(() => job = null);
      toast('$e');
    }
  }

  Future<void> exportReport() async {
    setState(() => exporting = true);
    try {
      final res = await engine!.post('export', {'path': path});
      toast('Saved ${res['pdf'] ?? res['html']}');
    } catch (e) {
      toast('$e');
    } finally {
      if (mounted) setState(() => exporting = false);
    }
  }

  Future<void> updateTools() async {
    try {
      var j = Json.from(await engine!.post('update-tools'));
      setState(() => updateJob = j);
      j = await engine!.poll(
        j,
        (v) => mounted ? setState(() => updateJob = v) : null,
      );
      setState(() => updateJob = null);
      if (j['state'] == 'done') {
        final res = Json.from(j['result']);
        setState(() => toolInfo = Json.from(res['status']));
        final failed = (res['results'] as List)
            .where((x) => '${x[1]}'.startsWith('failed'))
            .map((x) => x[0])
            .toList();
        toast(
          failed.isEmpty
              ? 'Scanners and rules are up to date.'
              : 'Updated - could not update: ${failed.join(', ')}',
        );
      } else {
        toast('Update failed: ${j['error']}');
      }
    } catch (e) {
      setState(() => updateJob = null);
      toast('$e');
    }
  }

  Future<void> runLive(View v) async {
    final target = liveTarget[v]!.text.trim();
    if (target.isEmpty) return;
    try {
      final body = v == View.web
          ? {
              'url': target,
              'nuclei': liveNuclei,
              'zap': liveZap || liveActive,
              'active': liveActive,
            }
          : {'host': target, 'lynis': liveLynis};
      var j = Json.from(
        await engine!.post(v == View.web ? 'web' : 'server', body),
      );
      setState(() => liveJob[v] = j);
      j = await engine!.poll(
        j,
        (x) => mounted ? setState(() => liveJob[v] = x) : null,
      );
      setState(() {
        liveJob[v] = null;
        if (j['state'] == 'done') liveReport[v] = Json.from(j['result']);
      });
      if (j['state'] != 'done') toast('${j['error']}');
    } catch (e) {
      setState(() => liveJob[v] = null);
      toast('$e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _rail(),
          Expanded(child: _main()),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------- rail: the manila folder
  Widget _railLabel(String t) => Container(
    width: double.infinity,
    margin: const EdgeInsets.only(top: S.s5, bottom: S.s2),
    padding: const EdgeInsets.only(top: S.s3),
    decoration: const BoxDecoration(
      border: Border(top: BorderSide(color: C.ink, width: 1.5)),
    ),
    child: Text(t.toUpperCase(), style: T.label()),
  );

  Widget _item({
    required Widget child,
    required bool current,
    required VoidCallback onTap,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 2),
    child: Material(
      color: current ? C.ink : Colors.transparent,
      borderRadius: BorderRadius.circular(R.md),
      child: InkWell(
        onTap: onTap,
        hoverColor: C.manilaDeep,
        borderRadius: BorderRadius.circular(R.md),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: S.s3, vertical: 9),
          child: child,
        ),
      ),
    ),
  );

  Widget _rail() {
    final rulesDate = toolInfo['rules_date'] as String?;
    final templates = toolInfo['nuclei_templates'] as int? ?? 0;
    return Container(
      width: 268,
      color: C.manila,
      padding: const EdgeInsets.fromLTRB(S.s4, S.s5, S.s4, S.s4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('CASEFILE', style: T.display(28)),
          const SizedBox(height: S.s1),
          Text('security, one check at a time', style: T.type(12)),
          const SizedBox(height: S.s4),
          Btn(
            'Open project folder',
            icon: Ph.folderOpen,
            wide: true,
            onTap: engine == null ? null : pickFolder,
          ),
          _railLabel('Case files'),
          Expanded(
            child: projects.isEmpty
                ? Padding(
                    padding: const EdgeInsets.symmetric(horizontal: S.s3),
                    child: Text(
                      'No case files yet. Open a project folder to start one.',
                      style: T.type(13),
                    ),
                  )
                : ListView(
                    primary: false,
                    children: [
                      for (final p in projects)
                        Builder(
                          builder: (_) {
                            final cur =
                                view == View.project && p['path'] == path;
                            final fg = cur ? C.paper : C.ink;
                            return _item(
                              current: cur,
                              onTap: () => openProject(p['path']),
                              child: Row(
                                children: [
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          p['name'],
                                          overflow: TextOverflow.ellipsis,
                                          style: T.ui(
                                            14.5,
                                            w: FontWeight.w700,
                                            color: fg,
                                            height: 1.3,
                                          ),
                                        ),
                                        Text(
                                          '${_short(p['last_scan'])}${p['open'] != null ? ' · ${p['open']} open' : ''}',
                                          maxLines: 1,
                                          overflow: TextOverflow.ellipsis,
                                          style: T.type(
                                            11.5,
                                            color: fg.withValues(alpha: .75),
                                            height: 1.3,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                  Text(
                                    '${p['score'] ?? '–'}',
                                    style: T.display(19, color: fg),
                                  ),
                                ],
                              ),
                            );
                          },
                        ),
                    ],
                  ),
          ),
          _railLabel('Live checks'),
          for (final (v, ic, label) in [
            (View.web, Ph.globeSimple, 'Website / API'),
            (View.server, Ph.hardDrives, 'Server'),
          ])
            _item(
              current: view == v,
              onTap: () => setState(() => view = v),
              child: Row(
                children: [
                  Icon(ic, size: 18, color: view == v ? C.paper : C.ink),
                  const SizedBox(width: S.s2),
                  Text(
                    label,
                    style: T.ui(
                      14.5,
                      w: FontWeight.w500,
                      color: view == v ? C.paper : C.ink,
                      height: 1.3,
                    ),
                  ),
                ],
              ),
            ),
          _railLabel('Scanners'),
          Wrap(
            spacing: 12,
            runSpacing: 6,
            children: [
              for (final e in tools.entries)
                Tooltip(
                  message: e.value == true
                      ? '${e.key} ${versions[e.key] ?? ''}'.trim()
                      : '${e.key}: not installed',
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Mark(e.value == true ? 'pass' : 'unchecked'),
                      const SizedBox(width: 5),
                      Text(e.key, style: T.type(11.5)),
                    ],
                  ),
                ),
            ],
          ),
          const SizedBox(height: S.s2),
          Text(
            [
              if (rulesDate != null)
                'Rules ${_short('$rulesDate 00:00').split(' ').take(2).join(' ')}',
              if (templates > 0) '${_thousands(templates)} Nuclei templates',
            ].join(' · '),
            style: T.type(11.5),
          ),
          const SizedBox(height: S.s2),
          updateJob != null
              ? Row(
                  children: [
                    const Spinner(size: 12),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        (List<Json>.from(updateJob!['steps']).first['note'] ??
                                'Updating…')
                            as String,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: T.type(11.5),
                      ),
                    ),
                  ],
                )
              : Btn(
                  'Update scanners & rules',
                  icon: Ph.arrowsClockwise,
                  kind: BtnKind.line,
                  small: true,
                  onTap: engine == null ? null : updateTools,
                ),
        ],
      ),
    );
  }

  static String _thousands(int n) => n.toString().replaceAllMapped(
    RegExp(r'\B(?=(\d{3})+(?!\d))'),
    (_) => ',',
  );

  /// "2026-11-11 09:59" -> "11 Nov 09:59"
  static String _short(String? when) {
    if (when == null || when.length < 16) return 'not scanned';
    const m = [
      'Jan',
      'Feb',
      'Mar',
      'Apr',
      'May',
      'Jun',
      'Jul',
      'Aug',
      'Sep',
      'Oct',
      'Nov',
      'Dec',
    ];
    return '${int.parse(when.substring(8, 10))} ${m[int.parse(when.substring(5, 7)) - 1]} ${when.substring(11, 16)}';
  }

  // ---------------------------------------------------------------- main area
  Widget _main() {
    if (bootError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(S.s6),
          child: Text(bootError!, style: T.type(14, color: C.stamp)),
        ),
      );
    }
    if (engine == null) return const Center(child: Spinner(size: 24));
    final body = switch (view) {
      View.start => _start(),
      View.project => _project(),
      View.web || View.server => _live(view),
    };
    return Scrollbar(
      controller: mainScroll,
      child: SingleChildScrollView(
        controller: mainScroll,
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 1180),
            child: Padding(
              padding: const EdgeInsets.fromLTRB(S.s6, S.s6, S.s6, S.s7),
              child: body,
            ),
          ),
        ),
      ),
    );
  }

  Widget _start() => Padding(
    padding: const EdgeInsets.only(top: S.s5),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'EVERY CHECK.',
          style: T.display(76).copyWith(letterSpacing: -2, height: .95),
        ),
        Text(
          'ONE BY ONE.',
          style: T
              .display(76, color: C.stamp)
              .copyWith(letterSpacing: -2, height: .95),
        ),
        const SizedBox(height: S.s5),
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 680),
          child: Text.rich(
            TextSpan(
              style: T.ui(19, color: C.ink2),
              children: [
                TextSpan(
                  text:
                      'Open a project folder. Casefile works out what it is made of (Express API, Flutter, Electron, Next.js), '
                      'runs Semgrep, Gitleaks, OSV and its own rules for that stack, maps every API route, then walks '
                      '$checkCount checklist items from OWASP and the CWE Top 25. Each item gets a pass, a fail, '
                      '"not used here", or an honest "not checked" - never a silent pass. Secrets are shown like this: ',
                ),
                WidgetSpan(
                  alignment: PlaceholderAlignment.middle,
                  child: Container(width: 120, height: 18, color: C.ink),
                ),
                const TextSpan(text: '.'),
              ],
            ),
          ),
        ),
        const SizedBox(height: S.s5),
        Btn('Open project folder', icon: Ph.folderOpen, onTap: pickFolder),
        const SizedBox(height: S.s7),
        Container(
          padding: const EdgeInsets.only(top: S.s4),
          decoration: const BoxDecoration(
            border: Border(top: BorderSide(color: C.ink, width: 1.5)),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (final (n, t) in [
                (
                  '01',
                  'Tools find the patterns: injection, secrets in git history, packages with known holes or malware (updated daily).',
                ),
                (
                  '02',
                  'Every finding says what can happen and when it is a false alarm. Unsure? Ask Claude to read the code around it.',
                ),
                (
                  '03',
                  'Every scan is kept. The next one shows what is new and what you fixed. Export a PDF report for clients.',
                ),
              ])
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.only(right: S.s5),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(n, style: T.display(28)),
                        const SizedBox(height: S.s2),
                        Text(t, style: T.ui(13.5, color: C.ink2)),
                      ],
                    ),
                  ),
                ),
            ],
          ),
        ),
      ],
    ),
  );

  /// Folder tab + manila band: the case file's cover.
  Widget _cover({
    required String tab,
    required String title,
    required Widget below,
    List<Widget> actions = const [],
  }) => Stack(
    children: [
      Padding(
        padding: const EdgeInsets.only(top: 30),
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.fromLTRB(S.s6, S.s5, S.s6, S.s5),
          decoration: const BoxDecoration(
            color: C.manila,
            borderRadius: BorderRadius.only(
              topRight: Radius.circular(R.md),
              bottomLeft: Radius.circular(R.md),
              bottomRight: Radius.circular(R.md),
            ),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title.toUpperCase(),
                      style: T.display(44).copyWith(letterSpacing: -1),
                    ),
                    const SizedBox(height: S.s2),
                    below,
                  ],
                ),
              ),
              if (actions.isNotEmpty) ...[
                const SizedBox(width: S.s5),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    for (final a in actions)
                      Padding(
                        padding: const EdgeInsets.only(bottom: S.s2),
                        child: a,
                      ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
      Container(
        padding: const EdgeInsets.fromLTRB(18, 8, 18, 7),
        decoration: const BoxDecoration(
          color: C.manila,
          borderRadius: BorderRadius.vertical(top: Radius.circular(R.tab)),
        ),
        child: Text(
          tab.toUpperCase(),
          style: T
              .type(11.5, color: C.ink, w: FontWeight.w700, height: 1)
              .copyWith(letterSpacing: .7),
        ),
      ),
    ],
  );

  Widget _project() {
    final running = job != null;
    final parts = List<String>.from(
      (report?['stack'] as Map?)?['parts'] ?? const [],
    );
    final hasUrl = url.text.trim().isNotEmpty,
        hasSsh = ssh.text.trim().isNotEmpty;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _cover(
          tab: 'Case file · ${meta!['name']}',
          title: meta!['name'],
          actions: [
            Btn(
              report == null ? 'Run all checks' : 'Scan again',
              icon: Ph.magnifyingGlass,
              busy: running,
              onTap: running ? null : scan,
            ),
            if (report != null && !running)
              Btn(
                'Export report',
                icon: Ph.filePdf,
                kind: BtnKind.line,
                busy: exporting,
                onTap: exporting ? null : exportReport,
              ),
          ],
          below: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SelectableText(meta!['path'], style: T.type(13.5)),
              if (parts.isNotEmpty) ...[
                const SizedBox(height: S.s3),
                Wrap(
                  spacing: S.s2,
                  runSpacing: S.s2,
                  children: [
                    for (final p in parts)
                      SolidTag(p, fill: C.ink, on: C.paper),
                  ],
                ),
              ],
              const SizedBox(height: S.s4),
              Wrap(
                spacing: S.s4,
                runSpacing: S.s3,
                children: [
                  TypedField(
                    label: 'Website / API URL',
                    controller: url,
                    hint: 'https://api.yourapp.com',
                    onChanged: (_) => setState(() {}),
                    onSubmitted: (_) => saveTargets(),
                  ),
                  TypedField(
                    label: 'Server (user@host:port)',
                    controller: ssh,
                    hint: 'root@203.0.113.5',
                    width: 260,
                    onChanged: (_) => setState(() {}),
                    onSubmitted: (_) => saveTargets(),
                  ),
                ],
              ),
              const SizedBox(height: S.s4),
              Wrap(
                spacing: S.s5,
                runSpacing: S.s2,
                children: [
                  CheckOpt(
                    'Claude review (permissions, tenants, money · 5–15 min)',
                    value: optClaude,
                    onChanged: tools['claude'] == true
                        ? (v) => setState(() => optClaude = v)
                        : null,
                  ),
                  CheckOpt(
                    'Nuclei known-CVE check (website · ~3 min)',
                    value: optNuclei && hasUrl,
                    onChanged: tools['nuclei'] == true && hasUrl
                        ? (v) => setState(() => optNuclei = v)
                        : null,
                  ),
                  CheckOpt(
                    'ZAP crawl (website · 2–10 min)',
                    value: optZap && hasUrl,
                    onChanged: tools['zap'] == true && hasUrl
                        ? (v) => setState(() => optZap = v)
                        : null,
                  ),
                  CheckOpt(
                    'Lynis on the server (over SSH, read-only)',
                    value: optLynis && hasSsh,
                    onChanged: tools['lynis'] == true && hasSsh
                        ? (v) => setState(() => optLynis = v)
                        : null,
                  ),
                  CheckOpt(
                    'Include test files',
                    value: optTests,
                    onChanged: (v) => setState(() => optTests = v),
                  ),
                ],
              ),
            ],
          ),
        ),
        if (running)
          _running(job!)
        else if (report == null)
          Padding(
            padding: const EdgeInsets.fromLTRB(S.s2, S.s6, 0, 0),
            child: Text(
              'Not scanned yet. Press Run all checks.',
              style: T.ui(15, color: C.muted),
            ),
          )
        else
          ReportView(
            key: ValueKey('$path${report!['when']}'),
            engine: engine!,
            report: report!,
            meta: meta,
            projectPath: path,
            land: land,
            onReport: (r) => setState(() {
              report = r;
              land = false;
            }),
          ),
      ],
    );
  }

  Widget _running(Json j) {
    final steps = List<Json>.from(j['steps']);
    final done = steps
        .where((s) => s['state'] == 'done' || s['state'] == 'failed')
        .length;
    final filled = (done / steps.length * checkCount).round();
    return Padding(
      padding: const EdgeInsets.fromLTRB(S.s2, S.s6, S.s2, 0),
      child: Row(
        children: [
          Dial(
            states: List.generate(
              checkCount,
              (i) => i < filled
                  ? 'pass'
                  : i == filled
                  ? 'running'
                  : 'unchecked',
            ),
            big: '$done',
            small: '/${steps.length}',
            caption: 'steps finished',
          ),
          const SizedBox(width: S.s6),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('CHECKING…', style: T.display(44)),
                const SizedBox(height: S.s4),
                _steps(steps),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _steps(List<Json> steps) => Column(
    children: [
      for (final s in steps)
        Container(
          padding: const EdgeInsets.symmetric(vertical: 12),
          decoration: const BoxDecoration(
            border: Border(top: BorderSide(color: C.rule)),
          ),
          child: Row(
            children: [
              SizedBox(
                width: 22,
                child: s['state'] == 'running'
                    ? const Spinner()
                    : Mark(s['state']),
              ),
              const SizedBox(width: S.s3),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(s['name'], style: T.ui(15, w: FontWeight.w700)),
                    if ('${s['error'] ?? ''}${s['note'] ?? ''}'.isNotEmpty)
                      Text(
                        (s['error'] ?? '') != '' ? s['error'] : s['note'],
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: T.type(
                          12,
                          color: (s['error'] ?? '') != '' ? C.stamp : C.muted,
                        ),
                      ),
                  ],
                ),
              ),
              Text(
                s['state'] == 'done' ? '${s['count']} found' : '${s['state']}',
                style: T.type(13.5, color: C.ink),
              ),
            ],
          ),
        ),
    ],
  );

  Widget _live(View v) {
    final web = v == View.web;
    final j = liveJob[v], r = liveReport[v];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _cover(
          tab: 'Live check · ${web ? 'website / API' : 'server'}',
          title: web ? 'Website / API' : 'Server',
          below: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 760),
                child: Text(
                  web
                      ? 'Headers, cookies, HTTPS, CORS and exposed .env / .git files - the checks the browser extensions do - plus '
                            'Nuclei (known CVEs, updated daily) and an optional OWASP ZAP crawl. Works for the API behind a desktop app too.'
                      : 'Which database and app ports answer from the internet (with a control scan, because this connection fakes '
                            'some ports), SSH algorithms, and optionally a Lynis hardening audit over SSH. Use the server\'s own IP: '
                            'a name behind Cloudflare points to Cloudflare, not to your server.',
                  style: T.type(13.5),
                ),
              ),
              const SizedBox(height: S.s4),
              Wrap(
                crossAxisAlignment: WrapCrossAlignment.end,
                spacing: S.s4,
                runSpacing: S.s3,
                children: [
                  TypedField(
                    label: web ? 'URL' : 'Server (user@host:port)',
                    controller: liveTarget[v]!,
                    hint: web ? 'https://api.yourapp.com' : 'root@203.0.113.5',
                    width: 380,
                    onSubmitted: (_) => runLive(v),
                  ),
                  if (web) ...[
                    CheckOpt(
                      'Nuclei',
                      value: liveNuclei,
                      onChanged: tools['nuclei'] == true
                          ? (x) => setState(() => liveNuclei = x)
                          : null,
                    ),
                    CheckOpt(
                      'ZAP crawl',
                      value: liveZap,
                      onChanged: tools['zap'] == true
                          ? (x) => setState(() => liveZap = x)
                          : null,
                    ),
                    CheckOpt(
                      'ZAP attack scan (localhost / LAN only)',
                      value: liveActive,
                      onChanged: tools['zap'] == true
                          ? (x) => setState(() => liveActive = x)
                          : null,
                    ),
                  ] else
                    CheckOpt(
                      'Lynis over SSH (read-only, 2–4 min)',
                      value: liveLynis,
                      onChanged: tools['lynis'] == true
                          ? (x) => setState(() => liveLynis = x)
                          : null,
                    ),
                  Btn(
                    'Check',
                    icon: Ph.magnifyingGlass,
                    busy: j != null,
                    onTap: j != null ? null : () => runLive(v),
                  ),
                ],
              ),
              if (web) ...[
                const SizedBox(height: S.s3),
                Text(
                  "The attack scan sends real attack requests. Casefile refuses it on anything that isn't your own machine or LAN - "
                  'run your app locally to use it, never against production.',
                  style: T.ui(13, color: C.ink2),
                ),
              ] else ...[
                const SizedBox(height: S.s3),
                Text(
                  'Lynis is copied to a temporary folder on the server, runs its read-only audit, prints the report and deletes '
                  'the folder. It uses your normal SSH key and never asks for a password.',
                  style: T.ui(13, color: C.ink2),
                ),
              ],
            ],
          ),
        ),
        if (j != null)
          Padding(
            padding: const EdgeInsets.only(top: S.s6),
            child: _steps(List<Json>.from(j['steps'])),
          )
        else if (r != null)
          ReportView(
            key: ValueKey('$v${r['when']}'),
            engine: engine!,
            report: r,
            onReport: (x) => setState(() => liveReport[v] = x),
          ),
      ],
    );
  }
}
