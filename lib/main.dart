import 'package:flutter/material.dart';
import 'package:encrypt/encrypt.dart' as encrypt;

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Criptografia App',
      theme: ThemeData(
        brightness: Brightness.dark,
        primarySwatch: Colors.blueGrey,
        scaffoldBackgroundColor: Colors.black,
        appBarTheme: AppBarTheme(
          backgroundColor: Colors.blueGrey[900],
        ),
        textTheme: TextTheme(
          bodyMedium: TextStyle(fontSize: 18.0, color: Colors.white70),
          bodyLarge: TextStyle(fontSize: 16.0, color: Colors.white54),
          headlineMedium: TextStyle(fontSize: 20.0, color: Colors.white),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: Colors.grey[800],
          labelStyle: TextStyle(color: Colors.white70),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8.0),
            borderSide: BorderSide.none,
          ),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.blueGrey[700], // Cor de fundo
            foregroundColor: Colors.white, // Cor do texto
            padding: EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
          ),
        ),
      ),
      home: MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final _controller = TextEditingController();
  String textoCriptografado = '';
  String textoDescriptografado = '';

  // Chave e IV compartilhados para criptografia e descriptografia
  final key = encrypt.Key.fromLength(32); // Gera uma chave de 256 bits (32 bytes)
  final iv = encrypt.IV.fromLength(16);  // Gera um IV de 128 bits (16 bytes)

  void criptografarAES() {
    final encrypter = encrypt.Encrypter(encrypt.AES(key));

    final encrypted = encrypter.encrypt(_controller.text, iv: iv);
    setState(() {
      textoCriptografado = encrypted.base64;
    });
  }

  void descriptografarAES() {
    final encrypter = encrypt.Encrypter(encrypt.AES(key));

    final decrypted = encrypter.decrypt64(textoCriptografado, iv: iv);
    setState(() {
      textoDescriptografado = decrypted;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Criptografia AES e RSA', style: Theme.of(context).textTheme.headlineMedium),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            TextField(
              controller: _controller,
              decoration: InputDecoration(
                labelText: 'Texto para criptografar',
              ),
            ),
            SizedBox(height: 16),
            Row(
              children: [
                ElevatedButton(
                  onPressed: criptografarAES,
                  child: Text('Criptografar'),
                ),
                SizedBox(width: 16),
                ElevatedButton(
                  onPressed: descriptografarAES,
                  child: Text('Descriptografar'),
                ),
              ],
            ),
            SizedBox(height: 16),
            Text(
              'Texto Criptografado:',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            Text(textoCriptografado, style: Theme.of(context).textTheme.bodyMedium),
            SizedBox(height: 16),
            Text(
              'Texto Descriptografado:',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            Text(textoDescriptografado, style: Theme.of(context).textTheme.bodyMedium),
          ],
        ),
      ),
    );
  }
}
