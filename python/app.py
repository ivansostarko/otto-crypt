from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
import os, base64, uuid
from otto_crypt import OttoCrypt, KeyExchange

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-not-for-production")

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
TMP_DIR = os.path.join(os.path.dirname(__file__), "tmp")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

def parse_options(form, mode):
    which = form.get("mode", "password")
    if which == "password":
        pw = form.get("password", "")
        if not pw:
            raise ValueError("Password required")
        return {"password": pw}
    if which == "x25519":
        if mode == "encrypt":
            rcpt = form.get("recipient_public", "")
            if not rcpt:
                raise ValueError("Recipient public key required")
            return {"recipient_public": rcpt}
        else:
            sk = form.get("sender_secret", "")
            if not sk:
                raise ValueError("Sender secret key required")
            return {"sender_secret": sk}
    if which == "raw":
        rk = form.get("raw_key", "")
        if not rk:
            raise ValueError("Raw key (32 bytes) required")
        return {"raw_key": rk}
    raise ValueError("Unknown mode")

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", text_result=None, text_error=None)

@app.route("/text/encrypt", methods=["POST"])
def text_encrypt():
    try:
        plaintext = request.form.get("plaintext", "")
        opts = parse_options(request.form, mode="encrypt")
        o = OttoCrypt()
        cipher, header = o.encrypt_string(plaintext.encode("utf-8"), options=opts)
        return render_template(
            "index.html",
            text_result={
                "action": "encrypt",
                "cipher_b64": base64.b64encode(cipher).decode(),
                "header_b64": base64.b64encode(header).decode(),
            },
            text_error=None,
        )
    except Exception as e:
        return render_template("index.html", text_result=None, text_error=f"Encrypt error: {e}")

@app.route("/text/decrypt", methods=["POST"])
def text_decrypt():
    try:
        cipher_b64 = request.form.get("cipher_b64", "")
        header_b64 = request.form.get("header_b64", "")
        opts = parse_options(request.form, mode="decrypt")
        cipher = base64.b64decode(cipher_b64)
        header = base64.b64decode(header_b64)
        o = OttoCrypt()
        plain = o.decrypt_string(cipher, header, options=opts)
        return render_template(
            "index.html",
            text_result={"action": "decrypt", "plaintext": plain.decode("utf-8", "replace")},
            text_error=None,
        )
    except Exception as e:
        return render_template("index.html", text_result=None, text_error=f"Decrypt error: {e}")

@app.route("/file/encrypt", methods=["POST"])
def file_encrypt():
    try:
        if "file" not in request.files or request.files["file"].filename == "":
            flash("No file selected", "error")
            return redirect(url_for("index"))
        f = request.files["file"]
        opts = parse_options(request.form, mode="encrypt")
        in_name = f.filename
        uid = str(uuid.uuid4())
        src = os.path.join(UPLOAD_DIR, uid + "_" + in_name)
        f.save(src)
        out_name = in_name + ".otto"
        dst = os.path.join(TMP_DIR, uid + "_" + out_name)
        o = OttoCrypt()
        o.encrypt_file(src, dst, options=opts)
        return send_file(dst, as_attachment=True, download_name=out_name)
    except Exception as e:
        flash(f"File encrypt error: {e}", "error")
        return redirect(url_for("index"))
    finally:
        # best-effort cleanup later; send_file may keep file open until sent
        pass

@app.route("/file/decrypt", methods=["POST"])
def file_decrypt():
    try:
        if "encfile" not in request.files or request.files["encfile"].filename == "":
            flash("No file selected", "error")
            return redirect(url_for("index"))
        f = request.files["encfile"]
        opts = parse_options(request.form, mode="decrypt")
        in_name = f.filename
        uid = str(uuid.uuid4())
        src = os.path.join(UPLOAD_DIR, uid + "_" + in_name)
        f.save(src)
        base = in_name[:-5] if in_name.endswith(".otto") else in_name
        out_name = (base or "output") + ".dec"
        dst = os.path.join(TMP_DIR, uid + "_" + out_name)
        o = OttoCrypt()
        o.decrypt_file(src, dst, options=opts)
        return send_file(dst, as_attachment=True, download_name=out_name)
    except Exception as e:
        flash(f"File decrypt error: {e}", "error")
        return redirect(url_for("index"))
    finally:
        pass

@app.route("/keys", methods=["GET"])
def keys():
    try:
        kp = KeyExchange.generate_keypair()
        return jsonify({
            "secret_base64": base64.b64encode(kp["secret"]).decode(),
            "public_base64": base64.b64encode(kp["public"]).decode(),
            "secret_hex": kp["secret"].hex(),
            "public_hex": kp["public"].hex(),
            "note": "Store secret securely; share public with senders."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)
