import Foundation
import IvanSostarkoOttoCrypt

struct CLI {
    static func parseFlag(_ name: String) -> String? {
        let prefix = "--\(name)="
        for a in CommandLine.arguments.dropFirst() {
            if a.hasPrefix(prefix) {
                return String(a.dropFirst(prefix.count))
            }
        }
        return nil
    }
    static func usage() {
        print(\"\"\"
OTTO Crypt Swift Demo

USAGE:
  otto-swift-demo keygen

  otto-swift-demo text:encrypt [--password=PWD | --recipient-public=B64|HEX|RAW | --raw-key=B64|HEX|RAW] --in=\"PLAINTEXT\"
  otto-swift-demo text:decrypt [--password=PWD | --sender-secret=B64|HEX|RAW | --raw-key=B64|HEX|RAW] --cipher-b64=CT --header-b64=HDR

  otto-swift-demo file:encrypt --in=/path/in --out=/path/out.otto [--password=PWD | --recipient-public=... | --raw-key=...]
  otto-swift-demo file:decrypt --in=/path/in.otto --out=/path/out.dec [--password=PWD | --sender-secret=... | --raw-key=...]
\"\"\")
    }
}

func buildOptions(enc: Bool) -> Options {
    var opt = Options()
    if let pw = CLI.parseFlag("password") { opt.password = pw }
    if enc, let rp = CLI.parseFlag("recipient-public") { opt.recipientPublic = rp }
    if !enc, let ss = CLI.parseFlag("sender-secret") { opt.senderSecret = ss }
    if let rk = CLI.parseFlag("raw-key") { opt.rawKey = rk }
    return opt
}

let args = CommandLine.arguments.dropFirst()
guard let cmd = args.first else { CLI.usage(); exit(1) }

switch cmd {
case "keygen":
    let kp = KeyExchange.generateKeypair()
    print("X25519 Public (base64): \(kp.publicKey.base64EncodedString())")
    print("X25519 Secret (base64): \(kp.secret.base64EncodedString())")

case "text:encrypt":
    var opt = buildOptions(enc: true)
    guard let pt = CLI.parseFlag("in")?.data(using: .utf8) else {
        print("Missing --in"); exit(2)
    }
    let otto = OttoCrypt()
    do {
        let r = try otto.encryptString(pt, options: opt)
        print("cipher_b64=\(r.cipherAndTag.base64EncodedString())")
        print("header_b64=\(r.header.base64EncodedString())")
    } catch {
        print("Error: \(error)"); exit(3)
    }

case "text:decrypt":
    var opt = buildOptions(enc: false)
    guard let cb64 = CLI.parseFlag("cipher-b64"),
          let hb64 = CLI.parseFlag("header-b64"),
          let c = Data(base64Encoded: cb64),
          let h = Data(base64Encoded: hb64) else {
        print("Missing or invalid --cipher-b64/--header-b64"); exit(2)
    }
    let otto = OttoCrypt()
    do {
        let p = try otto.decryptString(c, header: h, options: opt)
        print(String(data: p, encoding: .utf8) ?? "<non-utf8>")
    } catch {
        print("Error: \(error)"); exit(3)
    }

case "file:encrypt":
    var opt = buildOptions(enc: true)
    guard let inp = CLI.parseFlag("in"),
          let outp = CLI.parseFlag("out") else {
        print("Missing --in/--out"); exit(2)
    }
    let otto = OttoCrypt()
    do {
        try otto.encryptFile(inputPath: inp, outputPath: outp, options: opt)
        print("Encrypted -> \(outp)")
    } catch {
        print("Error: \(error)"); exit(3)
    }

case "file:decrypt":
    var opt = buildOptions(enc: false)
    guard let inp = CLI.parseFlag("in"),
          let outp = CLI.parseFlag("out") else {
        print("Missing --in/--out"); exit(2)
    }
    let otto = OttoCrypt()
    do {
        try otto.decryptFile(inputPath: inp, outputPath: outp, options: opt)
        print("Decrypted -> \(outp)")
    } catch {
        print("Error: \(error)"); exit(3)
    }

default:
    CLI.usage()
    exit(1)
}
