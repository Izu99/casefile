// The case file body: verdict (dial + stamp + counts), then the checklist one item at a
// time, every finding with filters, or the route map. Shared by project scans and live checks.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'engine.dart';
import 'icons.dart';
import 'tokens.dart';
import 'widgets.dart';

class ReportView extends StatefulWidget {
  const ReportView({
    super.key,
    required this.engine,
    required this.report,
    required this.onReport,
    this.projectPath,
    this.meta,
    this.land = false,
  });
  final Engine engine;
  final Json report;
  final ValueChanged<Json> onReport;
  final String? projectPath; // null for live checks: no ignore / verify there
  final Json? meta;
  final bool land;

  @override
  State<ReportView> createState() => _ReportViewState();
}

class _ReportViewState extends State<ReportView> {
  String tab = 'checklist';
  final open = <String>{};
  final q = TextEditingController();
  String sev = '', tool = '';
  bool onlyOpenRoutes = false;
  final verifying = <String>{};

  Json get r => widget.report;
  List<Json> get checks => List<Json>.from(r['checks']);
  List<Json> get findings => List<Json>.from(r['findings']);
  List<Json> get routes => List<Json>.from(r['routes'] ?? const []);

  void toast(String m) => ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(m, style: T.ui(13.5, color: C.paper)),
      backgroundColor: C.ink,
      behavior: SnackBarBehavior.floating,
      width: 560,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(R.pill),
      ),
    ),
  );

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _verdict(),
        _tabs(),
        if (tab == 'checklist') ..._checklist(),
        if (tab == 'findings') ..._findings(),
        if (tab == 'routes') ..._routes(),
      ],
    );
  }

  // ---------------------------------------------------------------- verdict
  Widget _verdict() {
    final unchecked = checks.where((c) => c['status'] == 'unchecked').length;
    final na = checks.where((c) => c['status'] == 'na').length;
    final openCount = r['open'] as int;
    final diff = r['diff'] as Map?;
    final errors = Map<String, dynamic>.from(r['errors'] ?? {});
    final counts = Map<String, dynamic>.from(r['counts']);
    final project = widget.projectPath != null;
    final hints = <String>[
      if (project &&
          checks.any(
            (c) => c['kind'] == 'claude' && c['status'] == 'unchecked',
          ))
        'Tick Claude review to check permissions, tenants and money logic.',
      if (project &&
          (widget.meta?['url'] ?? '') == '' &&
          checks.any((c) => c['kind'] == 'web' && c['status'] != 'na'))
        'Add the website URL for the live checks.',
      if (project &&
          (widget.meta?['ssh'] ?? '') == '' &&
          checks.any((c) => c['kind'] == 'server' && c['status'] != 'na'))
        'Add the server for the port and SSH checks.',
    ];
    final caption = [
      'checks passed',
      if (unchecked > 0) '$unchecked not checked',
      if (na > 0) '$na not used here',
    ].join(' · ');
    return Padding(
      padding: const EdgeInsets.fromLTRB(S.s2, S.s6, S.s2, S.s5),
      child: Row(
        children: [
          Dial(
            states: checks.map((c) => c['status'] as String).toList(),
            big: '${r['passed']}',
            small: '/${r['looked']}',
            caption: caption,
          ),
          const SizedBox(width: S.s6),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  crossAxisAlignment: WrapCrossAlignment.center,
                  spacing: S.s6,
                  runSpacing: S.s4,
                  children: [
                    Stamp(
                      openCount == 0 ? 'All clear' : '$openCount open',
                      clear: openCount == 0,
                      land: widget.land,
                    ),
                    Text(
                      'Scanned ${r['when']}',
                      style: T.type(13, color: C.muted),
                    ),
                  ],
                ),
                const SizedBox(height: S.s5),
                Wrap(
                  spacing: S.s2,
                  runSpacing: S.s2,
                  children: [
                    for (final s in severities)
                      SevChip(s, count: counts[s] as int),
                  ],
                ),
                if (diff != null && diff['since'] != null) ...[
                  const SizedBox(height: S.s4),
                  if (diff['reset'] == true)
                    Text(
                      "Casefile's checks changed since ${diff['since']} - new and fixed will show again from the next scan.",
                      style: T.type(13.5),
                    )
                  else
                    Text.rich(
                      TextSpan(
                        style: T.type(13.5),
                        children: [
                          TextSpan(text: 'Since ${diff['since']}: '),
                          TextSpan(
                            text: '${(diff['new'] as List).length} new',
                            style: const TextStyle(
                              fontWeight: FontWeight.w700,
                              color: C.ink,
                            ),
                          ),
                          const TextSpan(text: ', '),
                          TextSpan(
                            text: '${(diff['fixed'] as List).length} fixed',
                            style: const TextStyle(
                              fontWeight: FontWeight.w700,
                              color: C.ink,
                            ),
                          ),
                          if ((diff['fixed'] as List).isNotEmpty)
                            TextSpan(
                              text:
                                  ' - ${(diff['fixed'] as List).take(3).map((f) => (f['title'] as String).characters.take(50)).join('; ')}',
                            ),
                        ],
                      ),
                    ),
                ],
                if (errors.isNotEmpty) ...[
                  const SizedBox(height: S.s3),
                  Text(
                    '${errors.entries.map((e) => '${e.key}: ${e.value}').join('\n')}\nItems those scanners cover are marked "not checked".',
                    style: T.type(13, color: C.stamp),
                  ),
                ],
                if (hints.isNotEmpty) ...[
                  const SizedBox(height: S.s3),
                  Text(hints.join(' '), style: T.type(13, color: C.ink2)),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------- tabs
  Widget _tabs() {
    Widget t(String id, String label) {
      final on = tab == id;
      return InkWell(
        onTap: () => setState(() => tab = id),
        borderRadius: const BorderRadius.vertical(top: Radius.circular(R.tab)),
        child: Container(
          padding: const EdgeInsets.fromLTRB(18, 10, 18, 9),
          decoration: BoxDecoration(
            color: on ? C.ink : null,
            borderRadius: const BorderRadius.vertical(
              top: Radius.circular(R.tab),
            ),
          ),
          child: Text(
            label,
            style: T.ui(
              13.5,
              w: FontWeight.w700,
              color: on ? C.paper : C.ink,
              height: 1.2,
            ),
          ),
        ),
      );
    }

    final tools = findings.map((f) => f['tool'] as String).toSet().toList()
      ..sort();
    final noLogin = routes
        .where((x) => x['auth'] != true && x['public'] != true)
        .length;
    // Tabs on one line, their filters on the next: at 1024 px both don't fit side by side.
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          decoration: const BoxDecoration(
            border: Border(bottom: BorderSide(color: C.ink, width: 1.5)),
          ),
          margin: const EdgeInsets.only(top: S.s4),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              t('checklist', 'Checklist (${checks.length})'),
              const SizedBox(width: S.s1),
              t('findings', 'All findings (${findings.length})'),
              if (routes.isNotEmpty) ...[
                const SizedBox(width: S.s1),
                t(
                  'routes',
                  'Routes (${routes.length}${noLogin > 0 ? ' · $noLogin no login' : ''})',
                ),
              ],
            ],
          ),
        ),
        if (tab == 'findings')
          Padding(
            padding: const EdgeInsets.fromLTRB(S.s3, S.s3, 0, S.s1),
            child: Wrap(
              spacing: S.s2,
              runSpacing: S.s2,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                SizedBox(
                  width: 220,
                  child: TextField(
                    controller: q,
                    onChanged: (_) => setState(() {}),
                    style: T.type(13.5, color: C.ink, height: 1.2),
                    decoration: InputDecoration(
                      isDense: true,
                      hintText: 'search file or text',
                      hintStyle: T.type(13.5, color: C.muted, height: 1.2),
                      prefixIcon: const Icon(
                        Ph.magnifyingGlass,
                        size: 16,
                        color: C.ink2,
                      ),
                      prefixIconConstraints: const BoxConstraints(minWidth: 32),
                      filled: true,
                      fillColor: C.sheet,
                      contentPadding: const EdgeInsets.symmetric(vertical: 9),
                      enabledBorder: const UnderlineInputBorder(
                        borderSide: BorderSide(color: C.ink2, width: 1.5),
                      ),
                      focusedBorder: const UnderlineInputBorder(
                        borderSide: BorderSide(color: C.ink, width: 2.5),
                      ),
                    ),
                  ),
                ),
                _drop(
                  sev,
                  ['', ...severities],
                  'all severities',
                  (v) => setState(() => sev = v),
                ),
                _drop(
                  tool,
                  ['', ...tools],
                  'all tools',
                  (v) => setState(() => tool = v),
                ),
              ],
            ),
          ),
        if (tab == 'routes')
          Padding(
            padding: const EdgeInsets.fromLTRB(S.s3, S.s3, 0, 0),
            child: CheckOpt(
              'Only routes without login',
              value: onlyOpenRoutes,
              onChanged: (v) => setState(() => onlyOpenRoutes = v),
            ),
          ),
      ],
    );
  }

  Widget _drop(
    String value,
    List<String> items,
    String empty,
    ValueChanged<String> on,
  ) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10),
    decoration: const BoxDecoration(
      color: C.sheet,
      border: Border(bottom: BorderSide(color: C.ink2, width: 1.5)),
    ),
    child: DropdownButtonHideUnderline(
      child: DropdownButton<String>(
        value: value,
        isDense: true,
        dropdownColor: C.sheet,
        style: T.ui(13.5),
        icon: const Icon(Ph.caretDown, size: 14, color: C.ink),
        items: [
          for (final i in items)
            DropdownMenuItem(
              value: i,
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 8),
                child: Text(i.isEmpty ? empty : i),
              ),
            ),
        ],
        onChanged: (v) => on(v ?? ''),
      ),
    ),
  );

  // ---------------------------------------------------------------- checklist
  List<Widget> _checklist() {
    final areas = <String>[];
    for (final c in checks) {
      if (!areas.contains(c['area'])) areas.add(c['area']);
    }
    var n = 0;
    final out = <Widget>[];
    for (final a in areas) {
      out.add(
        Padding(
          padding: const EdgeInsets.fromLTRB(S.s3, S.s5, 0, S.s2),
          child: Text(a.toUpperCase(), style: T.label(color: C.muted)),
        ),
      );
      for (final c in checks.where((c) => c['area'] == a)) {
        n++;
        out.add(_checkRow(c, n));
      }
    }
    return out;
  }

  List<Json> _hits(Json c) {
    final tags = Set<String>.from(c['match'] ?? const []);
    return findings
        .where(
          (f) =>
              f['check'] == c['id'] ||
              List<String>.from(f['tags'] ?? const []).any(tags.contains),
        )
        .toList();
  }

  Widget _checkRow(Json c, int n) {
    final id = c['id'] as String;
    final isOpen = open.contains(id);
    final st = c['status'] as String;
    final na = st == 'na';
    final hits = _hits(c);
    final label = switch (st) {
      'pass' => 'passed',
      'fail' => '${c['count']} found',
      'na' => 'not used',
      _ => 'not checked',
    };
    final note = c['note'] as String?;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Material(
          color: isOpen ? C.sheet : Colors.transparent,
          child: InkWell(
            hoverColor: C.sheet,
            onTap: () =>
                setState(() => isOpen ? open.remove(id) : open.add(id)),
            child: Container(
              decoration: const BoxDecoration(
                border: Border(top: BorderSide(color: C.rule)),
              ),
              padding: const EdgeInsets.symmetric(
                horizontal: S.s3,
                vertical: 13,
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SizedBox(
                    width: 58,
                    child: Text(
                      'Fig. ${n.toString().padLeft(2, '0')}',
                      style: T.type(12, color: C.muted, height: 1.7),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.only(top: 4, right: S.s3),
                    child: Mark(st),
                  ),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          c['title'],
                          style: T.ui(
                            15,
                            w: FontWeight.w700,
                            color: na ? C.muted : C.ink,
                          ),
                        ),
                        const SizedBox(height: 2),
                        if (!na)
                          Text(c['why'], style: T.ui(13.5, color: C.muted)),
                        if (note != null)
                          Padding(
                            padding: const EdgeInsets.only(top: 4),
                            child: Text(
                              note,
                              style: T.type(12.5, color: na ? C.muted : C.ink2),
                            ),
                          ),
                      ],
                    ),
                  ),
                  const SizedBox(width: S.s3),
                  Text(
                    label.toUpperCase(),
                    style: T
                        .label(
                          color: st == 'fail'
                              ? C.stamp
                              : st == 'pass'
                              ? C.ink
                              : C.muted,
                        )
                        .copyWith(height: 1.7, fontSize: 11.5),
                  ),
                  Padding(
                    padding: const EdgeInsets.only(left: 8, top: 2),
                    child: AnimatedRotation(
                      turns: isOpen ? .5 : 0,
                      duration: const Duration(milliseconds: 150),
                      child: const Icon(Ph.caretDown, size: 15),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
        if (isOpen)
          Container(
            color: C.sheet,
            padding: const EdgeInsets.fromLTRB(
              58 + 14 + S.s3 * 2,
              0,
              S.s3,
              S.s4,
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text.rich(
                  TextSpan(
                    children: [
                      TextSpan(
                        text: 'CHECKED WITH  ',
                        style: T.label(color: C.ink),
                      ),
                      TextSpan(
                        text: List<String>.from(
                          c['by'] ?? const [],
                        ).join(' · '),
                        style: T.type(12.5),
                      ),
                    ],
                  ),
                ),
                if ((c['refs'] as List?)?.isNotEmpty == true)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text(
                      List<String>.from(c['refs']).join(' · '),
                      style: T.type(12, color: C.muted),
                    ),
                  ),
                if (st == 'pass' && hits.isEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: S.s3),
                    child: Text(
                      'Nothing found. Marked-safe findings for this item don\'t count against it.',
                      style: T.ui(13.5, color: C.ink2),
                    ),
                  ),
                if (st == 'unchecked')
                  Padding(
                    padding: const EdgeInsets.only(top: S.s3),
                    child: Text(
                      c['kind'] == 'claude'
                          ? 'Only a reader can judge this one: tick Claude review and scan again.'
                          : c['kind'] == 'web'
                          ? 'Needs the website URL (or the Website tab).'
                          : c['kind'] == 'server'
                          ? 'Needs the server address (or the Server tab).'
                          : 'The scanner for this item did not finish - see the error above.',
                      style: T.ui(13.5, color: C.ink2),
                    ),
                  ),
                for (final f in hits.take(25)) _finding(f),
                if (hits.length > 25) _more(hits.length - 25),
              ],
            ),
          ),
      ],
    );
  }

  Widget _more(int n) => Padding(
    padding: const EdgeInsets.all(S.s3),
    child: Align(
      alignment: Alignment.centerLeft,
      child: Text(
        '+ $n more - see All findings with a filter.',
        style: T.ui(13.5, w: FontWeight.w700),
      ),
    ),
  );

  // ---------------------------------------------------------------- findings
  List<Widget> _findings() {
    final ql = q.text.toLowerCase();
    final list = findings
        .where(
          (f) =>
              (sev.isEmpty || f['severity'] == sev) &&
              (tool.isEmpty || f['tool'] == tool) &&
              (ql.isEmpty ||
                  '${f['title']} ${f['file']} ${f['message']}'
                      .toLowerCase()
                      .contains(ql)),
        )
        .toList();
    if (list.isEmpty) {
      return [
        Padding(
          padding: const EdgeInsets.all(S.s5),
          child: Text('Nothing matches.', style: T.ui(14, color: C.muted)),
        ),
      ];
    }
    return [
      for (final f in list.take(200))
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: S.s3),
          child: _finding(f),
        ),
      if (list.length > 200) _more(list.length - 200),
    ];
  }

  Widget _label(String text, String body) => Padding(
    padding: const EdgeInsets.only(top: S.s2),
    child: Text.rich(
      TextSpan(
        children: [
          TextSpan(
            text: '$text  ',
            style: T.label(color: C.ink),
          ),
          TextSpan(text: body, style: T.ui(13.5)),
        ],
      ),
    ),
  );

  Widget _finding(Json f) {
    final fp = f['fp'] as String;
    final v = f['verdict'] as Map?;
    final ignored = f['ignored'] as Map?;
    final live = widget.projectPath == null;
    final isFile =
        !live &&
        (f['file'] ?? '') != '' &&
        ![
          'web',
          'nuclei',
          'zap',
          'ports',
          'ssh-audit',
          'lynis',
        ].contains(f['tool']);
    final msg = (f['message'] ?? '') as String;
    final ex = f['explain'] as Map?;
    final adv = List<Json>.from(f['advisories'] ?? const []);
    return Opacity(
      opacity: ignored != null ? .55 : 1,
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(vertical: S.s4),
        decoration: const BoxDecoration(
          border: Border(top: BorderSide(color: C.rule)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SevChip(f['severity']),
                const SizedBox(width: S.s3),
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.only(top: 3),
                    child: SelectableText(
                      f['title'],
                      style: T.ui(15, w: FontWeight.w700),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Wrap(
              crossAxisAlignment: WrapCrossAlignment.center,
              spacing: 8,
              children: [
                if (isFile)
                  Tooltip(
                    message: 'Open in editor',
                    child: InkWell(
                      onTap: () => widget.engine
                          .post('open', {
                            'path': widget.projectPath,
                            'file': f['file'],
                            'line': f['line'],
                          })
                          .catchError((e) => toast('$e')),
                      child: Text(
                        '${f['file']}${(f['line'] ?? 0) > 0 ? ':${f['line']}' : ''}',
                        style: T
                            .type(13.5)
                            .copyWith(
                              decoration: TextDecoration.underline,
                              decorationColor: C.ink2,
                            ),
                      ),
                    ),
                  )
                else
                  SelectableText('${f['file']}', style: T.type(13.5)),
                Text(
                  '${f['tool']}${f['rule'] != null && f['rule'] != f['title'] && f['tool'] != 'osv' ? ' · ${f['rule']}' : ''}'
                      .toUpperCase(),
                  style: T.label(color: C.muted).copyWith(fontSize: 10.5),
                ),
              ],
            ),
            if ((f['snippet'] ?? '') != '') Snippet(f['snippet']),
            if (f['note'] != null)
              Padding(
                padding: const EdgeInsets.only(top: S.s3),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Padding(
                      padding: EdgeInsets.only(top: 2, right: 6),
                      child: Icon(Ph.info, size: 15, color: C.ink),
                    ),
                    Expanded(
                      child: Text(f['note'], style: T.type(13, color: C.ink)),
                    ),
                  ],
                ),
              ),
            if (msg.isNotEmpty && msg != f['title'])
              Padding(
                padding: const EdgeInsets.only(top: S.s2),
                child: Text(
                  msg.length > 500 ? '${msg.substring(0, 500)}…' : msg,
                  style: T.ui(13.5, color: C.ink2),
                ),
              ),
            if (adv.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: S.s2),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    for (final a in adv.take(6))
                      Padding(
                        padding: const EdgeInsets.only(top: 3),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Padding(
                              padding: const EdgeInsets.only(top: 6, right: 8),
                              child: _dot(a['severity']),
                            ),
                            Expanded(
                              child: Text.rich(
                                TextSpan(
                                  children: [
                                    TextSpan(
                                      text: '${a['id']}  ',
                                      style: T.type(
                                        12.5,
                                        color: C.ink,
                                        w: FontWeight.w700,
                                      ),
                                    ),
                                    TextSpan(
                                      text: '${a['summary']}',
                                      style: T.ui(13),
                                    ),
                                    if ((a['fixed'] ?? '') != '')
                                      TextSpan(
                                        text: '  fixed in ${a['fixed']}',
                                        style: T.type(12.5),
                                      ),
                                  ],
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    if (adv.length > 6)
                      Text('+ ${adv.length - 6} more', style: T.type(12.5)),
                  ],
                ),
              ),
            if (ex?['risk'] != null) _label('WHAT CAN HAPPEN', ex!['risk']),
            if (ex?['ok'] != null) _label("WHEN IT'S FINE", ex!['ok']),
            if ((f['fix'] ?? '') != '') _label('FIX', f['fix']),
            if (v != null)
              Container(
                width: double.infinity,
                margin: const EdgeInsets.only(top: S.s3),
                padding: const EdgeInsets.all(S.s4),
                color: C.paper,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SolidTag(
                      'Claude: ${v['verdict']}',
                      fill: v['verdict'] == 'real'
                          ? C.stamp
                          : v['verdict'] == 'false-positive'
                          ? C.ink
                          : C.amber,
                      on: v['verdict'] == 'unsure' ? C.ink : Colors.white,
                    ),
                    const SizedBox(height: S.s2),
                    Text('${v['reason'] ?? ''}', style: T.ui(13.5)),
                    if ((v['fix'] ?? '') != '') _label('FIX', v['fix']),
                  ],
                ),
              ),
            if (ignored != null)
              Padding(
                padding: const EdgeInsets.only(top: S.s2),
                child: Text(
                  'Marked safe ${ignored['at'] ?? ''}: ${ignored['reason']}',
                  style: T.type(12.5),
                ),
              ),
            const SizedBox(height: S.s3),
            Wrap(
              spacing: S.s2,
              runSpacing: S.s2,
              children: [
                if (!live && v == null && f['tool'] != 'claude')
                  Btn(
                    verifying.contains(fp)
                        ? (_verifyNote ?? 'Claude is reading the code…')
                        : 'Ask Claude: is this real?',
                    icon: Ph.robot,
                    small: true,
                    busy: verifying.contains(fp),
                    onTap: () => _verify(fp),
                  ),
                if (!live)
                  ignored != null
                      ? Btn(
                          'Undo "safe"',
                          kind: BtnKind.line,
                          small: true,
                          onTap: () => _ignore(fp, null),
                        )
                      : Btn(
                          'Mark safe…',
                          icon: Ph.eyeSlash,
                          kind: BtnKind.line,
                          small: true,
                          onTap: () => _askReason(f),
                        ),
                Btn(
                  'Copy for Claude Code',
                  icon: Ph.copy,
                  kind: BtnKind.line,
                  small: true,
                  onTap: () => _copy(f),
                ),
                if ((f['link'] ?? '') != '')
                  Btn(
                    'Read more',
                    icon: Ph.arrowSquareOut,
                    kind: BtnKind.text,
                    small: true,
                    onTap: () => widget.engine.post('link', {'url': f['link']}),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _dot(String sev) => Container(
    width: 8,
    height: 8,
    decoration: BoxDecoration(
      shape: BoxShape.circle,
      color: sev == 'low' ? null : sevFill(sev),
      border: sev == 'low' ? Border.all(color: C.ink, width: 1.5) : null,
    ),
  );

  void _copy(Json f) {
    final where = '${f['file']}${(f['line'] ?? 0) > 0 ? ':${f['line']}' : ''}';
    final text = [
      'Security finding from Casefile${widget.projectPath != null ? ' in ${widget.projectPath}' : ''}:',
      '${f['severity'].toString().toUpperCase()}: ${f['title']}',
      'Where: $where',
      if ((f['message'] ?? '') != '' && f['message'] != f['title'])
        'Detail: ${f['message']}',
      if (f['note'] != null) 'Context: ${f['note']}',
      if ((f['fix'] ?? '') != '') 'Suggested fix: ${f['fix']}',
      '',
      'First read the code around it (and any global middleware) and tell me if it is real. '
          'If it is, fix it, show how you verified the fix, and run the tests.',
    ].join('\n');
    Clipboard.setData(ClipboardData(text: text));
    toast('Copied. Paste it into Claude Code in that project.');
  }

  // ---------------------------------------------------------------- routes
  List<Widget> _routes() {
    final list = routes
        .where(
          (x) => !onlyOpenRoutes || (x['auth'] != true && x['public'] != true),
        )
        .toList();
    Widget cell(Widget w, double width) => SizedBox(width: width, child: w);
    return [
      Padding(
        padding: const EdgeInsets.fromLTRB(S.s3, S.s4, S.s3, S.s2),
        child: Text(
          'Every route the API answers, with the middleware Express runs before it (in order). '
          'Login: a lock means a login check runs first. Role: a permission check (requireRole, ownerOnly...) runs too.',
          style: T.ui(13.5, color: C.ink2),
        ),
      ),
      Container(
        padding: const EdgeInsets.symmetric(horizontal: S.s3, vertical: 8),
        decoration: const BoxDecoration(
          border: Border(bottom: BorderSide(color: C.ink, width: 1.5)),
        ),
        child: Row(
          children: [
            cell(Text('METHOD', style: T.label()), 74),
            Expanded(child: Text('PATH', style: T.label())),
            cell(Text('LOGIN', style: T.label()), 86),
            cell(Text('ROLE', style: T.label()), 54),
            cell(Text('MIDDLEWARE', style: T.label()), 300),
          ],
        ),
      ),
      for (final x in list)
        Container(
          padding: const EdgeInsets.symmetric(horizontal: S.s3, vertical: 8),
          decoration: const BoxDecoration(
            border: Border(bottom: BorderSide(color: C.rule)),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              cell(
                Text(
                  '${x['method']}',
                  style: T.type(13, color: C.ink, w: FontWeight.w700),
                ),
                74,
              ),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SelectableText(
                      '${x['path']}',
                      style: T.type(13.5, color: C.ink),
                    ),
                    InkWell(
                      onTap: widget.projectPath == null
                          ? null
                          : () => widget.engine.post('open', {
                              'path': widget.projectPath,
                              'file': x['file'],
                              'line': x['line'],
                            }),
                      child: Text(
                        '${x['file']}:${x['line']}',
                        style: T.type(11.5, color: C.muted),
                      ),
                    ),
                  ],
                ),
              ),
              cell(
                x['auth'] == true
                    ? const Align(
                        alignment: Alignment.centerLeft,
                        child: Icon(Ph.lockSimple, size: 17, color: C.ink),
                      )
                    : x['public'] == true
                    ? Text('public', style: T.type(12.5, color: C.muted))
                    : const Align(
                        alignment: Alignment.centerLeft,
                        child: SolidTag('NO', fill: C.stamp),
                      ),
                86,
              ),
              cell(
                x['role'] == true
                    ? const Align(
                        alignment: Alignment.centerLeft,
                        child: Icon(Ph.check, size: 17, color: C.ink),
                      )
                    : Text('-', style: T.type(12.5, color: C.muted)),
                54,
              ),
              cell(
                Text(
                  List<String>.from(x['mws'] ?? const []).join(' · '),
                  style: T.type(12, color: C.ink2),
                ),
                300,
              ),
            ],
          ),
        ),
    ];
  }

  // ---------------------------------------------------------------- actions
  String? _verifyNote;

  Future<void> _verify(String fp) async {
    setState(() => verifying.add(fp));
    try {
      final job = await widget.engine.poll(
        Json.from(
          await widget.engine.post('verify', {
            'path': widget.projectPath,
            'fp': fp,
          }),
        ),
        (j) {
          final note =
              (List<Json>.from(j['steps']).first['note'] ?? '') as String;
          if (mounted && note.isNotEmpty)
            setState(() => _verifyNote = 'Claude: $note');
        },
      );
      if (job['state'] == 'done') {
        widget.onReport(Json.from(job['result']));
      } else {
        toast('Claude failed: ${job['error']}');
      }
    } catch (e) {
      toast('$e');
    } finally {
      if (mounted) {
        setState(() {
          verifying.remove(fp);
          _verifyNote = null;
        });
      }
    }
  }

  Future<void> _ignore(String fp, String? reason) async {
    final rep = await widget.engine.post('ignore', {
      'path': widget.projectPath,
      'fp': fp,
      'reason': reason,
    });
    widget.onReport(Json.from(rep));
  }

  Future<void> _askReason(Json f) async {
    final c = TextEditingController();
    final reason = await showDialog<String>(
      context: context,
      barrierColor: C.ink.withValues(alpha: .45),
      builder: (ctx) => Dialog(
        backgroundColor: C.sheet,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(R.md),
        ),
        child: SizedBox(
          width: 520,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(S.s6, S.s5, S.s6, S.s5),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('MARK AS SAFE', style: T.display(28)),
                const SizedBox(height: S.s3),
                Text(f['title'], style: T.ui(13.5, color: C.muted)),
                const SizedBox(height: S.s3),
                TextField(
                  controller: c,
                  autofocus: true,
                  minLines: 3,
                  maxLines: 6,
                  style: T.type(13.5, color: C.ink),
                  decoration: InputDecoration(
                    hintText:
                        'Why is this not a problem? e.g. input is checked by validateObjectId() before this line',
                    hintStyle: T.type(13.5, color: C.muted),
                    hintMaxLines: 3,
                    filled: true,
                    fillColor: C.paper,
                    enabledBorder: const UnderlineInputBorder(
                      borderSide: BorderSide(color: C.ink, width: 1.5),
                    ),
                    focusedBorder: const UnderlineInputBorder(
                      borderSide: BorderSide(color: C.ink, width: 3),
                    ),
                  ),
                ),
                const SizedBox(height: S.s4),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    Btn(
                      'Cancel',
                      kind: BtnKind.text,
                      onTap: () => Navigator.pop(ctx),
                    ),
                    const SizedBox(width: S.s2),
                    Btn(
                      'Mark safe',
                      onTap: () => c.text.trim().isEmpty
                          ? null
                          : Navigator.pop(ctx, c.text.trim()),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
    if (reason != null) {
      await _ignore(f['fp'], reason);
      toast('Kept out of the score. It stays listed, faded, with your reason.');
    }
  }
}
