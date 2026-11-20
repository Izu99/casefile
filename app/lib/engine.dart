// Starts the Python scan engine (../casefile) and talks to its local API.
// The engine prints "PORT <n>" when ready and exits when our stdin pipe closes,
// so it never outlives this window.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

typedef Json = Map<String, dynamic>;

class Engine {
  Engine._(this._proc, this.base);
  final Process _proc;
  final String base;

  static Future<Engine> start() async {
    final dir = _findEngineDir();
    if (dir == null)
      throw 'Scan engine not found (looked for casefile/__main__.py next to the app).';
    final proc = await Process.start(
      'python3',
      ['-m', 'casefile'],
      workingDirectory: dir,
      environment: {'PYTHONUNBUFFERED': '1'},
    );
    final port = Completer<int>();
    final errors = StringBuffer();
    proc.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((
      l,
    ) {
      final m = RegExp(r'^PORT (\d+)').firstMatch(l);
      if (m != null && !port.isCompleted) port.complete(int.parse(m.group(1)!));
    });
    proc.stderr.transform(utf8.decoder).listen((e) {
      errors.write(e);
      stderr.write(e);
    });
    proc.exitCode.then((c) {
      if (!port.isCompleted)
        port.completeError('Scan engine stopped ($c): $errors');
    });
    final p = await port.future.timeout(const Duration(seconds: 20));
    return Engine._(proc, 'http://127.0.0.1:$p/api/');
  }

  // Installed: <bundle>/engine/casefile. Development: walk up from the binary to the repo.
  static String? _findEngineDir() {
    final env = Platform.environment['CASEFILE_ENGINE'];
    if (env != null && File('$env/casefile/__main__.py').existsSync())
      return env;
    var d = File(Platform.resolvedExecutable).parent;
    for (var i = 0; i < 9; i++) {
      for (final c in [d.path, '${d.path}/engine']) {
        if (File('$c/casefile/__main__.py').existsSync()) return c;
      }
      d = d.parent;
    }
    return null;
  }

  void stop() => _proc.kill();

  Future<dynamic> get(String path) async {
    final r = await http.get(Uri.parse(base + path));
    return _decode(r);
  }

  Future<dynamic> post(String path, [Json body = const {}]) async {
    final r = await http.post(
      Uri.parse(base + path),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    return _decode(r);
  }

  dynamic _decode(http.Response r) {
    final data = jsonDecode(utf8.decode(r.bodyBytes));
    if (r.statusCode >= 400)
      throw (data is Map ? data['error'] : null) ?? 'Error ${r.statusCode}';
    return data;
  }

  /// Polls a background job until it finishes; [onTick] gets each running view.
  Future<Json> poll(Json job, [void Function(Json)? onTick]) async {
    while (job['state'] == 'running') {
      onTick?.call(job);
      await Future.delayed(const Duration(milliseconds: 900));
      job = Json.from(await get('job/${job['id']}'));
    }
    return job;
  }
}
