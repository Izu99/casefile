// Shared pieces: the dot dial, the rubber stamp, solid chips, pill buttons, typed fields.
import 'dart:math';

import 'package:flutter/material.dart';

import 'tokens.dart';

/// One dot per checklist item around a ring: ink = passed, red = failed,
/// amber = running, hollow = not checked.
class Dial extends StatelessWidget {
  const Dial({
    super.key,
    required this.states,
    required this.big,
    required this.small,
    required this.caption,
    this.size = 250,
  });
  final List<String> states;
  final String big, small, caption;
  final double size;

  @override
  Widget build(BuildContext context) => SizedBox(
    width: size,
    height: size,
    child: Stack(
      alignment: Alignment.center,
      children: [
        CustomPaint(size: Size.square(size), painter: _DialPainter(states)),
        Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text.rich(
              TextSpan(
                children: [
                  TextSpan(text: big, style: T.display(size * .3)),
                  TextSpan(
                    text: small,
                    style: T.display(size * .1, color: C.muted),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: size * .55,
              child: Text(
                caption,
                textAlign: TextAlign.center,
                style: T.type(12, color: C.muted, height: 1.3),
              ),
            ),
          ],
        ),
      ],
    ),
  );
}

class _DialPainter extends CustomPainter {
  _DialPainter(this.states);
  final List<String> states;

  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero),
        r = size.width / 2 - 14,
        n = states.length;
    for (var i = 0; i < n; i++) {
      final a = i / n * 2 * pi - pi / 2;
      final p = c + Offset(cos(a), sin(a)) * r;
      switch (states[i]) {
        case 'pass':
          canvas.drawCircle(p, 6, Paint()..color = C.ink);
        case 'fail':
          canvas.drawCircle(p, 7.5, Paint()..color = C.stamp);
        case 'running':
          canvas.drawCircle(p, 6, Paint()..color = C.amber);
        case 'na':
          canvas.drawCircle(p, 2, Paint()..color = C.faint);
        default:
          canvas.drawCircle(
            p,
            5,
            Paint()
              ..color = C.muted
              ..style = PaintingStyle.stroke
              ..strokeWidth = 1.6,
          );
      }
    }
  }

  @override
  bool shouldRepaint(_DialPainter old) => old.states.join() != states.join();
}

/// The verdict, stamped at an angle. [land] plays the stamp-down thud once.
class Stamp extends StatelessWidget {
  const Stamp(this.text, {super.key, this.clear = false, this.land = false});
  final String text;
  final bool clear, land;

  @override
  Widget build(BuildContext context) {
    final color = clear ? C.ok : C.stamp;
    final box = Container(
      padding: const EdgeInsets.fromLTRB(18, 10, 18, 8),
      decoration: BoxDecoration(
        border: Border.all(color: color, width: 4),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        text.toUpperCase(),
        style: T.display(40, color: color).copyWith(letterSpacing: 1),
      ),
    );
    final reduce = MediaQuery.of(context).disableAnimations;
    if (!land || reduce)
      return Transform.rotate(angle: -6 * pi / 180, child: box);
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: 1),
      duration: const Duration(milliseconds: 420),
      curve: Curves.easeOutBack,
      builder: (_, t, child) => Opacity(
        opacity: t.clamp(0, 1),
        child: Transform.rotate(
          angle: (-14 + 8 * t) * pi / 180,
          child: Transform.scale(scale: 2.2 - 1.2 * t, child: child),
        ),
      ),
      child: box,
    );
  }
}

/// Severity as a solid chip - never a pale wash of its own colour.
class SevChip extends StatelessWidget {
  const SevChip(this.sev, {super.key, this.count});
  final String sev;
  final int? count;

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
    decoration: BoxDecoration(
      color: sevFill(sev),
      borderRadius: BorderRadius.circular(R.pill),
      border: sev == 'low' ? Border.all(color: C.ink, width: 1.5) : null,
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.baseline,
      textBaseline: TextBaseline.alphabetic,
      children: [
        if (count != null) ...[
          Text('$count', style: T.display(15, color: sevText(sev))),
          const SizedBox(width: 6),
        ],
        Text(
          sev,
          style: T.ui(13, w: FontWeight.w700, color: sevText(sev), height: 1.2),
        ),
      ],
    ),
  );
}

class SolidTag extends StatelessWidget {
  const SolidTag(
    this.text, {
    super.key,
    required this.fill,
    this.on = Colors.white,
  });
  final String text;
  final Color fill, on;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
    decoration: BoxDecoration(
      color: fill,
      borderRadius: BorderRadius.circular(R.pill),
    ),
    child: Text(
      text,
      style: T.ui(12, w: FontWeight.w700, color: on, height: 1.2),
    ),
  );
}

enum BtnKind { ink, line, red, text }

class Btn extends StatefulWidget {
  const Btn(
    this.label, {
    super.key,
    this.icon,
    this.onTap,
    this.kind = BtnKind.ink,
    this.small = false,
    this.busy = false,
    this.wide = false,
  });
  final String label;
  final IconData? icon;
  final VoidCallback? onTap;
  final BtnKind kind;
  final bool small, busy, wide;
  @override
  State<Btn> createState() => _BtnState();
}

class _BtnState extends State<Btn> {
  bool hover = false;
  @override
  Widget build(BuildContext context) {
    final enabled = widget.onTap != null && !widget.busy;
    final k = widget.kind;
    final bg = switch (k) {
      BtnKind.ink => hover ? const Color(0xFF2C2823) : C.ink,
      BtnKind.red => hover ? const Color(0xFFA82216) : C.stamp,
      BtnKind.line => hover ? C.ink : Colors.transparent,
      BtnKind.text => Colors.transparent,
    };
    final fg =
        (k == BtnKind.ink || k == BtnKind.red || (k == BtnKind.line && hover))
        ? C.paper
        : C.ink;
    final pad = widget.small
        ? const EdgeInsets.symmetric(horizontal: 14, vertical: 8)
        : const EdgeInsets.symmetric(horizontal: 18, vertical: 12);
    return Opacity(
      opacity: enabled || widget.busy ? 1 : .45,
      child: MouseRegion(
        cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
        onEnter: (_) => setState(() => hover = true),
        onExit: (_) => setState(() => hover = false),
        child: GestureDetector(
          onTap: enabled ? widget.onTap : null,
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 120),
            padding: pad,
            width: widget.wide ? double.infinity : null,
            decoration: BoxDecoration(
              color: bg,
              borderRadius: BorderRadius.circular(R.pill),
              border: k == BtnKind.line
                  ? Border.all(color: C.ink, width: 1.5)
                  : null,
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                if (widget.busy)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(
                        strokeWidth: 2.4,
                        color: fg,
                      ),
                    ),
                  )
                else if (widget.icon != null)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: Icon(
                      widget.icon,
                      size: widget.small ? 15 : 18,
                      color: fg,
                    ),
                  ),
                Text(
                  widget.label,
                  style: T
                      .ui(
                        widget.small ? 12.5 : 13.5,
                        w: k == BtnKind.text
                            ? FontWeight.w500
                            : FontWeight.w700,
                        color: fg,
                        height: 1.2,
                      )
                      .copyWith(
                        decoration: k == BtnKind.text
                            ? TextDecoration.underline
                            : null,
                      ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// A typed field: label above, sheet fill, ink underline.
class TypedField extends StatelessWidget {
  const TypedField({
    super.key,
    required this.label,
    required this.controller,
    this.hint = '',
    this.width = 300,
    this.onSubmitted,
    this.onChanged,
  });
  final String label, hint;
  final TextEditingController controller;
  final double width;
  final ValueChanged<String>? onSubmitted, onChanged;

  @override
  Widget build(BuildContext context) => SizedBox(
    width: width,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label.toUpperCase(), style: T.label()),
        const SizedBox(height: 5),
        TextField(
          controller: controller,
          onSubmitted: onSubmitted,
          onChanged: onChanged,
          style: T.type(14, color: C.ink, height: 1.2),
          decoration: InputDecoration(
            isDense: true,
            hintText: hint,
            hintStyle: T.type(14, color: C.muted, height: 1.2),
            filled: true,
            fillColor: C.sheet,
            contentPadding: const EdgeInsets.symmetric(
              horizontal: 10,
              vertical: 11,
            ),
            enabledBorder: const UnderlineInputBorder(
              borderSide: BorderSide(color: C.ink, width: 1.5),
            ),
            focusedBorder: const UnderlineInputBorder(
              borderSide: BorderSide(color: C.ink, width: 3),
            ),
          ),
        ),
      ],
    ),
  );
}

class CheckOpt extends StatelessWidget {
  const CheckOpt(
    this.label, {
    super.key,
    required this.value,
    required this.onChanged,
  });
  final String label;
  final bool value;
  final ValueChanged<bool>? onChanged;
  @override
  Widget build(BuildContext context) => Opacity(
    opacity: onChanged == null ? .45 : 1,
    child: InkWell(
      onTap: onChanged == null ? null : () => onChanged!(!value),
      borderRadius: BorderRadius.circular(R.sm),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: 22,
              height: 22,
              child: Checkbox(
                value: value,
                onChanged: onChanged == null
                    ? null
                    : (v) => onChanged!(v ?? false),
              ),
            ),
            const SizedBox(width: 6),
            Text(label, style: T.ui(13.5)),
          ],
        ),
      ),
    ),
  );
}

/// Code snippet on ink. Runs of █ from the engine render as solid redaction bars.
class Snippet extends StatelessWidget {
  const Snippet(this.text, {super.key});
  final String text;
  @override
  Widget build(BuildContext context) {
    final spans = <InlineSpan>[];
    for (final m in RegExp(r'█+|[^█]+').allMatches(text)) {
      final s = m.group(0)!;
      spans.add(
        s.startsWith('█')
            ? TextSpan(
                text: s,
                style: const TextStyle(
                  color: Colors.black,
                  backgroundColor: Colors.black,
                ),
              )
            : TextSpan(text: s),
      );
    }
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(top: S.s3),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: C.ink,
        borderRadius: BorderRadius.circular(R.sm),
      ),
      child: SelectableText.rich(
        TextSpan(
          children: spans,
          style: T.type(12.5, color: C.code, height: 1.5),
        ),
      ),
    );
  }
}

class Spinner extends StatelessWidget {
  const Spinner({super.key, this.size = 14});
  final double size;
  @override
  Widget build(BuildContext context) => SizedBox(
    width: size,
    height: size,
    child: const CircularProgressIndicator(strokeWidth: 2.5, color: C.ink),
  );
}

class Mark extends StatelessWidget {
  const Mark(this.status, {super.key});
  final String status;
  @override
  Widget build(BuildContext context) => status == 'na'
      ? const SizedBox(
          width: 14,
          height: 14,
          child: Center(
            child: CircleAvatar(radius: 2.5, backgroundColor: C.faint),
          ),
        )
      : Container(
          width: 14,
          height: 14,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: status == 'pass' || status == 'done'
                ? C.ink
                : status == 'fail' || status == 'failed'
                ? C.stamp
                : null,
            border: status == 'unchecked' || status == 'waiting'
                ? Border.all(color: C.muted, width: 2)
                : null,
          ),
        );
}
