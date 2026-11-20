import 'dart:io';
import 'dart:math';
import 'package:shared_preferences/shared_preferences.dart';

const baseUrl = 'http://api.vuln-shop.lk';

class Api {
  HttpClient client() {
    final c = HttpClient();
    c.badCertificateCallback = (cert, host, port) => true;
    return c;
  }

  Future<void> saveLogin(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('auth_token', token);
    print('saved token $token');
  }

  String makeResetCode() {
    return Random().nextInt(999999).toString();
  }
}
