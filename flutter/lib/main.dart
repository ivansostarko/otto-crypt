import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:otto_crypt/otto_crypt.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const OttoDemoApp());
}

class OttoDemoApp extends StatelessWidget {
  const OttoDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OTTO Crypt Demo',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.indigo),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  OttoCrypt? _otto;
  String _status = "Initializing...";

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 2, vsync: this);
    _init();
  }

  Future<void> _init() async {
    try {
      final o = await OttoCrypt.create(withSodium: true);
      setState(() {
        _otto = o;
        _status = "Ready";
      });
    } catch (e) {
      setState(() {
        _status = "Init error: $e";
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("OTTO Crypt Demo"),
        bottom: TabBar(
          controller: _tabs,
          tabs: const [Tab(text: "Text"), Tab(text: "Files")],
        ),
      ),
      body: _otto == null
          ? Center(child: Text(_status))
          : TabBarView(
              controller: _tabs,
              children: [
                TextTab(otto: _otto!),
                FilesTab(otto: _otto!),
              ],
            ),
    );
  }
}

// ---------------- TEXT TAB ----------------

enum KeyMode { password, x25519, raw }

class TextTab extends StatefulWidget {
  final OttoCrypt otto;
  const TextTab({super.key, required this.otto});

  @override
  State<TextTab> createState() => _TextTabState();
}

class _TextTabState extends State<TextTab> {
  KeyMode _encMode = KeyMode.password;
  KeyMode _decMode = KeyMode.password;

  final _pwEnc = TextEditingController();
  final _rcptPubEnc = TextEditingController();
  final _rawEnc = TextEditingController();

  final _plain = TextEditingController();

  final _cipherB64 = TextEditingController();
  final _headerB64 = TextEditingController();

  final _pwDec = TextEditingController();
  final _senderSkDec = TextEditingController();
  final _rawDec = TextEditingController();

  String _outText = "";

  @override
  void dispose() {
    _pwEnc.dispose();
    _rcptPubEnc.dispose();
    _rawEnc.dispose();
    _plain.dispose();
    _cipherB64.dispose();
    _headerB64.dispose();
    _pwDec.dispose();
    _senderSkDec.dispose();
    _rawDec.dispose();
    super.dispose();
  }

  OttoOptions _buildEncOptions() {
    final opt = OttoOptions();
    switch (_encMode) {
      case KeyMode.password:
        opt.password = _pwEnc.text;
        break;
      case KeyMode.x25519:
        opt.recipientPublic = _rcptPubEnc.text;
        break;
      case KeyMode.raw:
        opt.rawKey = _rawEnc.text;
        break;
    }
    return opt;
  }

  OttoOptions _buildDecOptions() {
    final opt = OttoOptions();
    switch (_decMode) {
      case KeyMode.password:
        opt.password = _pwDec.text;
        break;
      case KeyMode.x25519:
        opt.senderSecret = _senderSkDec.text;
        break;
      case KeyMode.raw:
        opt.rawKey = _rawDec.text;
        break;
    }
    return opt;
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: ListView(
        children: [
          const Text("Encrypt", style: TextStyle(fontWeight: FontWeight.bold)),
          Wrap(
            spacing: 12,
            children: [
              ChoiceChip(
                label: const Text("Password"),
                selected: _encMode == KeyMode.password,
                onSelected: (_) => setState(() => _encMode = KeyMode.password),
              ),
              ChoiceChip(
                label: const Text("X25519"),
                selected: _encMode == KeyMode.x25519,
                onSelected: (_) => setState(() => _encMode = KeyMode.x25519),
              ),
              ChoiceChip(
                label: const Text("Raw 32-byte key"),
                selected: _encMode == KeyMode.raw,
                onSelected: (_) => setState(() => _encMode = KeyMode.raw),
              ),
            ],
          ),
          const SizedBox(height: 8),
          if (_encMode == KeyMode.password)
            TextField(controller: _pwEnc, decoration: const InputDecoration(labelText: "Password"), obscureText: true),
          if (_encMode == KeyMode.x25519)
            TextField(controller: _rcptPubEnc, decoration: const InputDecoration(labelText: "Recipient public (base64/hex/raw)")),
          if (_encMode == KeyMode.raw)
            TextField(controller: _rawEnc, decoration: const InputDecoration(labelText: "Raw key (32 bytes base64/hex/raw)")),
          const SizedBox(height: 8),
          TextField(
            controller: _plain,
            minLines: 3,
            maxLines: 6,
            decoration: const InputDecoration(labelText: "Plaintext"),
          ),
          const SizedBox(height: 8),
          FilledButton(
            onPressed: () async {
              try {
                final opt = _buildEncOptions();
                final r = await widget.otto.encryptString(Uint8List.fromList(utf8.encode(_plain.text)), opt);
                _cipherB64.text = base64.encode(r.cipherAndTag);
                _headerB64.text = base64.encode(r.header);
                setState(() {});
                if (!mounted) return;
                ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Encrypted")));
              } catch (e) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text("Error: $e")));
              }
            },
            child: const Text("Encrypt"),
          ),
          const SizedBox(height: 16),
          const Text("Decrypt", style: TextStyle(fontWeight: FontWeight.bold)),
          Wrap(
            spacing: 12,
            children: [
              ChoiceChip(
                label: const Text("Password"),
                selected: _decMode == KeyMode.password,
                onSelected: (_) => setState(() => _decMode = KeyMode.password),
              ),
              ChoiceChip(
                label: const Text("X25519"),
                selected: _decMode == KeyMode.x25519,
                onSelected: (_) => setState(() => _decMode = KeyMode.x25519),
              ),
              ChoiceChip(
                label: const Text("Raw 32-byte key"),
                selected: _decMode == KeyMode.raw,
                onSelected: (_) => setState(() => _decMode = KeyMode.raw),
              ),
            ],
          ),
          const SizedBox(height: 8),
          if (_decMode == KeyMode.password)
            TextField(controller: _pwDec, decoration: const InputDecoration(labelText: "Password"), obscureText: true),
          if (_decMode == KeyMode.x25519)
            TextField(controller: _senderSkDec, decoration: const InputDecoration(labelText: "Sender secret (base64/hex/raw)")),
          if (_decMode == KeyMode.raw)
            TextField(controller: _rawDec, decoration: const InputDecoration(labelText: "Raw key (32 bytes base64/hex/raw)")),
          const SizedBox(height: 8),
          TextField(controller: _cipherB64, minLines: 2, maxLines: 6, decoration: const InputDecoration(labelText: "Ciphertext+Tag (base64)")),
          TextField(controller: _headerB64, minLines: 2, maxLines: 6, decoration: const InputDecoration(labelText: "Header (base64)")),
          const SizedBox(height: 8),
          FilledButton(
            onPressed: () async {
              try {
                final opt = _buildDecOptions();
                final c = base64.decode(_cipherB64.text.trim());
                final h = base64.decode(_headerB64.text.trim());
                final p = await widget.otto.decryptString(Uint8List.fromList(c), Uint8List.fromList(h), opt);
                _outText = utf8.decode(p);
                setState(() {});
                if (!mounted) return;
                ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Decrypted")));
              } catch (e) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text("Error: $e")));
              }
            },
            child: const Text("Decrypt"),
          ),
          const SizedBox(height: 8),
          SelectableText(_outText),
          const SizedBox(height: 16),
          OutlinedButton(
            onPressed: () async {
              try {
                final kp = widget.otto.generateKeypair();
                if (!mounted) return;
                await showDialog(context: context, builder: (_) {
                  return AlertDialog(
                    title: const Text("X25519 Keypair"),
                    content: SelectableText("Public:\n${base64.encode(kp.publicKey)}\n\nSecret:\n${base64.encode(kp.secret)}"),
                    actions: [TextButton(onPressed: ()=>Navigator.pop(context), child: const Text("Close"))],
                  );
                });
              } catch (e) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text("Keygen error: $e")));
              }
            },
            child: const Text("Generate X25519 keypair"),
          ),
        ],
      ),
    );
  }
}

// ---------------- FILES TAB ----------------

class FilesTab extends StatefulWidget {
  final OttoCrypt otto;
  const FilesTab({super.key, required this.otto});

  @override
  State<FilesTab> createState() => _FilesTabState();
}

class _FilesTabState extends State<FilesTab> {
  KeyMode _mode = KeyMode.password;
  bool _encrypt = true;

  final _pw = TextEditingController();
  final _rcptPub = TextEditingController();
  final _raw = TextEditingController();
  final _senderSk = TextEditingController();

  String? _inputPath;
  String? _outputPath;
  String _status = "";

  @override
  void dispose() {
    _pw.dispose();
    _rcptPub.dispose();
    _raw.dispose();
    _senderSk.dispose();
    super.dispose();
  }

  OttoOptions _buildOptions() {
    final opt = OttoOptions();
    switch (_mode) {
      case KeyMode.password:
        opt.password = _pw.text;
        break;
      case KeyMode.x25519:
        if (_encrypt) {
          opt.recipientPublic = _rcptPub.text;
        } else {
          opt.senderSecret = _senderSk.text;
        }
        break;
      case KeyMode.raw:
        opt.rawKey = _raw.text;
        break;
    }
    return opt;
  }

  Future<void> _pickInput() async {
    final res = await FilePicker.platform.pickFiles(withData: false);
    if (res != null && res.files.isNotEmpty) {
      setState(() => _inputPath = res.files.single.path);
    }
  }

  Future<void> _suggestOutput() async {
    final docs = await getApplicationDocumentsDirectory();
    final inPath = _inputPath ?? "input.bin";
    final name = inPath.split(Platform.pathSeparator).last;
    final outName = _encrypt ? "$name.otto" : (name.endsWith(".otto") ? name.replaceAll(RegExp(r'\.otto$'), ".dec") : "$name.dec");
    setState(() => _outputPath = "${docs.path}/$outName");
  }

  Future<void> _run() async {
    if (_inputPath == null) { setState(()=>_status="Pick input file first"); return; }
    await _suggestOutput();
    if (_outputPath == null) { setState(()=>_status="No output path"); return; }
    setState(()=>_status="Working...");
    try {
      final opt = _buildOptions();
      if (_encrypt) {
        await widget.otto.encryptFile(_inputPath!, _outputPath!, opt);
      } else {
        await widget.otto.decryptFile(_inputPath!, _outputPath!, opt);
      }
      setState(()=>_status="Done: $_outputPath");
    } catch (e) {
      setState(()=>_status="Error: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: ListView(
        children: [
          Wrap(
            spacing: 12,
            children: [
              ChoiceChip(label: const Text("Encrypt"), selected: _encrypt, onSelected: (_) => setState(()=>_encrypt=true)),
              ChoiceChip(label: const Text("Decrypt"), selected: !_encrypt, onSelected: (_) => setState(()=>_encrypt=false)),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 12,
            children: [
              ChoiceChip(label: const Text("Password"), selected: _mode==KeyMode.password, onSelected: (_)=>setState(()=>_mode=KeyMode.password)),
              ChoiceChip(label: const Text("X25519"), selected: _mode==KeyMode.x25519, onSelected: (_)=>setState(()=>_mode=KeyMode.x25519)),
              ChoiceChip(label: const Text("Raw 32-byte key"), selected: _mode==KeyMode.raw, onSelected: (_)=>setState(()=>_mode=KeyMode.raw)),
            ],
          ),
          const SizedBox(height: 8),
          if (_mode == KeyMode.password)
            TextField(controller: _pw, obscureText: true, decoration: const InputDecoration(labelText: "Password")),
          if (_mode == KeyMode.x25519 && _encrypt)
            TextField(controller: _rcptPub, decoration: const InputDecoration(labelText: "Recipient public (base64/hex/raw)")),
          if (_mode == KeyMode.x25519 && !_encrypt)
            TextField(controller: _senderSk, decoration: const InputDecoration(labelText: "Sender secret (base64/hex/raw)")),
          if (_mode == KeyMode.raw)
            TextField(controller: _raw, decoration: const InputDecoration(labelText: "Raw key (32 bytes base64/hex/raw)")),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(child: Text(_inputPath ?? "No input selected")),
              const SizedBox(width: 12),
              OutlinedButton(onPressed: _pickInput, child: const Text("Pick input")),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(child: Text(_outputPath ?? "Output path will be suggested in app docs folder")),
              const SizedBox(width: 12),
              OutlinedButton(onPressed: _suggestOutput, child: const Text("Suggest output")),
            ],
          ),
          const SizedBox(height: 12),
          FilledButton(onPressed: _run, child: const Text("Run")),
          const SizedBox(height: 8),
          SelectableText(_status),
          const SizedBox(height: 12),
          const Text("Notes:", style: TextStyle(fontWeight: FontWeight.bold)),
          const Text(
            "• Works with any file: photos, PDFs, audio (mp3/wav), video (mp4), etc.\n"
            "• Outputs to the app documents directory by default.\n"
            "• For interop tests, copy .otto files between devices and use the same mode & keying material."
          ),
        ],
      ),
    );
  }
}
