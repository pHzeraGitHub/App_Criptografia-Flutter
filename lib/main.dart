import 'dart:convert';
import 'dart:math';
import 'dart:typed_data'; // Import necessário para Uint8List
import 'package:flutter/material.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:pointycastle/export.dart' as pc; // Importa todas as classes do PointyCastle

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

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
        textTheme: const TextTheme(
          bodyMedium: TextStyle(fontSize: 18.0, color: Colors.white70),
          bodyLarge: TextStyle(fontSize: 16.0, color: Colors.white54),
          headlineMedium: TextStyle(fontSize: 20.0, color: Colors.white),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: Colors.grey[800],
          labelStyle: const TextStyle(color: Colors.white70),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8.0),
            borderSide: BorderSide.none,
          ),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.blueGrey[700],
            foregroundColor: Colors.white,
            padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
          ),
        ),
      ),
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final _controller = TextEditingController();
  String textoCriptografado = '';
  String textoDescriptografado = '';

  // AES
  final key = encrypt.Key.fromLength(32); // Gera uma chave de 256 bits (32 bytes)
  final iv = encrypt.IV.fromLength(16); // Gera um IV de 128 bits (16 bytes)

  // RSA
  pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey>? chaveRSA;
  String algoritmoSelecionado = 'AES';
  final List<String> algoritmos = ['AES', 'RSA'];

  // Gera chaves RSA
  pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> generateRSAKeyPair() {
    final keyGen = pc.RSAKeyGenerator()
      ..init(pc.ParametersWithRandom(
        pc.RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 5),
        _secureRandom()));
    final pair = keyGen.generateKeyPair();
    return pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey>(
      pair.publicKey as pc.RSAPublicKey,
      pair.privateKey as pc.RSAPrivateKey,
    );
  }

  // Seed para o Fortuna Random
  pc.SecureRandom _secureRandom() {
    final secureRandom = pc.SecureRandom('Fortuna');
    final random = Random.secure();
    final seeds = List<int>.generate(32, (_) => random.nextInt(255));
    secureRandom.seed(pc.KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  // Função de criptografia AES
  void criptografarAES() {
    final encrypter = encrypt.Encrypter(encrypt.AES(key));
    final encrypted = encrypter.encrypt(_controller.text, iv: iv);
    setState(() {
      textoCriptografado = encrypted.base64;
    });
  }

  // Função de descriptografia AES
  void descriptografarAES() {
    final encrypter = encrypt.Encrypter(encrypt.AES(key));
    final decrypted = encrypter.decrypt64(textoCriptografado, iv: iv);
    setState(() {
      textoDescriptografado = decrypted;
    });
  }

  // Função de criptografia RSA
  String criptografarRSA(String texto, pc.RSAPublicKey publicKey) {
    final encrypter = encrypt.Encrypter(encrypt.RSA(publicKey: publicKey));
    final encrypted = encrypter.encrypt(texto);
    return encrypted.base64;
  }

  // Função de descriptografia RSA
  String descriptografarRSA(String textoCriptografado, pc.RSAPrivateKey privateKey) {
    final encrypter = encrypt.Encrypter(encrypt.RSA(privateKey: privateKey));
    final decrypted = encrypter.decrypt64(textoCriptografado);
    return decrypted;
  }

  // Função genérica de criptografia
  void criptografar() {
    if (algoritmoSelecionado == 'AES') {
      criptografarAES();
    } else if (algoritmoSelecionado == 'RSA' && chaveRSA != null) {
      final encrypted = criptografarRSA(_controller.text, chaveRSA!.publicKey);
      setState(() {
        textoCriptografado = encrypted;
      });
    }
  }

  // Função genérica de descriptografia
  void descriptografar() {
    if (algoritmoSelecionado == 'AES') {
      descriptografarAES();
    } else if (algoritmoSelecionado == 'RSA' && chaveRSA != null) {
      final decrypted = descriptografarRSA(textoCriptografado, chaveRSA!.privateKey);
      setState(() {
        textoDescriptografado = decrypted;
      });
    }
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
              decoration: const InputDecoration(
                labelText: 'Texto para criptografar',
              ),
            ),
            const SizedBox(height: 16),
            DropdownButton<String>(
              value: algoritmoSelecionado,
              items: algoritmos.map((String algoritmo) {
                return DropdownMenuItem<String>(
                  value: algoritmo,
                  child: Text(algoritmo),
                );
              }).toList(),
              onChanged: (String? novoAlgoritmo) {
                setState(() {
                  algoritmoSelecionado = novoAlgoritmo!;
                  if (algoritmoSelecionado == 'RSA') {
                    chaveRSA = generateRSAKeyPair(); // Gera as chaves RSA ao selecionar RSA
                  }
                });
              },
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                ElevatedButton(
                  onPressed: criptografar,
                  child: const Text('Criptografar'),
                ),
                const SizedBox(width: 16),
                ElevatedButton(
                  onPressed: descriptografar,
                  child: const Text('Descriptografar'),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Text(
              'Texto Criptografado:',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            Text(textoCriptografado, style: Theme.of(context).textTheme.bodyMedium),
            const SizedBox(height: 16),
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
