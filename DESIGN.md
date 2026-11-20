# Casefile — design

**Job:** desktop tool (Python GTK window + WebKit page). Pick a project → every check, one by one → a case file.

**Direction: declassified dossier.** Every scan is a case file on a manila folder; findings are typed
entries; secrets are shown under solid black redaction bars (which is also the real security rule: the
app never displays a full secret).

References (looked at 2026-11-11):
- Declassified CIA memo with redaction bars (Wikimedia, via fetch-world) → black bars, typewriter body, page number "-5-".
- "Secret Lock of Berard" engraving plate (Wellcome, CC-BY) → numbered "Fig." labels: each checklist item is a numbered figure, hairline rules, plate frame.
- SaaSFrame dot-ring "155h" dial → the hero: one dot per checklist item around a ring, giant number in the middle.

Palette: manila field #D8B97A (header band + sidebar), paper #F4EFE4 (sheets), ink #161412,
stamp red #C22A1E (fail stamps, critical), muted ink #5E574C. Pass = solid ink dot. Unchecked = hollow ring.
No tinted pairs: severity is a solid chip (white on red / ink on manila / white on ink) or a solid dot.

Type: Bowlby One (display numbers, stamps), Courier Prime (typed entries, file paths, code), Supreme (UI).
Shape: sharp sheets (2px), folder tab with 10px top corners, pills for buttons/chips, round dots.
Signature: the dot ring + rubber-stamp verdict ("6 OPEN" stamped in red at an angle).
Set-piece: stamp lands when a scan finishes (scale+rotate thud, reduced-motion = static); dots fill one by one as checks complete.
Icons: Phosphor regular. Boldness: 3 (tool used daily; boldness lives in the band, dial and stamp).
Window: min 1024×700; mouse first, Esc closes drawers.
