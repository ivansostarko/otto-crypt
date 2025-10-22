package com.ivansostarko.ottocrypt.demo

import android.app.Activity
import android.content.ContentResolver
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.ivansostarko.ottocrypt.android.Otto
import com.ivansostarko.ottocrypt.android.OttoResult
import com.ivansostarko.ottocrypt.demo.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.SecureRandom

class MainActivity : ComponentActivity() {
    private lateinit var b: ActivityMainBinding
    private var pickedUri: Uri? = null
    private var lastEncrypted: File? = null
    private var lastDecrypted: File? = null
    private var lastHeader: ByteArray? = null
    private var lastCipher: ByteArray? = null

    private val picker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
            pickedUri = uri
            b.txtFile.text = "Selected: $uri"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.btnGenKey.setOnClickListener {
            val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
            b.edtKey.setText(Base64.encodeToString(key, Base64.NO_WRAP))
            toast("Generated 32B key")
        }

        b.btnEncryptText.setOnClickListener {
            val key = loadKeyOrGenerate()
            val pt = b.edtPlain.text.toString().toByteArray()
            lifecycleScope.launch {
                try {
                    val res = withContext(Dispatchers.Default) { Otto.encryptString(pt, key) }
                    lastHeader = res.header
                    lastCipher = res.cipherAndTag
                    b.txtHeaderB64.text = "Header (B64): " + Base64.encodeToString(res.header, Base64.NO_WRAP)
                    b.txtCipherB64.text = "Cipher (B64): " + Base64.encodeToString(res.cipherAndTag, Base64.NO_WRAP)
                    toast("Text encrypted")
                } catch (e: Exception) {
                    toast("Encrypt failed: ${e.message}")
                }
            }
        }

        b.btnDecryptText.setOnClickListener {
            val key = decodeB64OrNull(b.edtKey.text.toString()) ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
            val header = lastHeader ?: decodeFromLabel(b.txtHeaderB64.text.toString())
            val cipher = lastCipher ?: decodeFromLabel(b.txtCipherB64.text.toString())
            if (header == null || cipher == null) { toast("No ciphertext/header to decrypt"); return@setOnClickListener }
            lifecycleScope.launch {
                try {
                    val pt = withContext(Dispatchers.Default) { Otto.decryptString(cipher, header, key) }
                    b.txtDecrypted.text = "Decrypted: " + String(pt)
                    toast("Text decrypted")
                } catch (e: Exception) {
                    toast("Decrypt failed: ${e.message}")
                }
            }
        }

        b.btnPickFile.setOnClickListener {
            picker.launch(arrayOf("*/*"))
        }

        b.btnEncryptFile.setOnClickListener {
            val uri = pickedUri ?: return@setOnClickListener toast("Pick a file first")
            val key = loadKeyOrGenerate()
            lifecycleScope.launch {
                try {
                    val src = withContext(Dispatchers.IO) { copyToTemp(uri) }
                    val out = File(cacheDir, src.name + ".otto")
                    withContext(Dispatchers.Default) { Otto.encryptFile(src, out, key) }
                    lastEncrypted = out
                    b.txtFileStatus.text = "Encrypted → ${out.absolutePath} (${out.length()} bytes)"
                    toast("File encrypted")
                } catch (e: Exception) {
                    toast("Encrypt failed: ${e.message}")
                }
            }
        }

        b.btnDecryptFile.setOnClickListener {
            val enc = lastEncrypted ?: return@setOnClickListener toast("Encrypt a file first")
            val key = loadKeyOrGenerate()
            lifecycleScope.launch {
                try {
                    val dec = File(cacheDir, enc.name + ".dec")
                    withContext(Dispatchers.Default) { Otto.decryptFile(enc, dec, key) }
                    lastDecrypted = dec
                    b.txtFileStatus.text = "Decrypted → ${dec.absolutePath} (${dec.length()} bytes)"
                    toast("File decrypted")
                } catch (e: Exception) {
                    toast("Decrypt failed: ${e.message}")
                }
            }
        }
    }

    private fun loadKeyOrGenerate(): ByteArray {
        val maybe = decodeB64OrNull(b.edtKey.text.toString())
        return if (maybe != null && maybe.size == 32) maybe else ByteArray(32).also {
            SecureRandom().nextBytes(it)
            b.edtKey.setText(Base64.encodeToString(it, Base64.NO_WRAP))
        }
    }

    private fun decodeB64OrNull(s: String?): ByteArray? = try {
        if (s.isNullOrBlank()) null else Base64.decode(s, Base64.NO_WRAP)
    } catch (_: Exception) { null }

    private fun decodeFromLabel(label: CharSequence): ByteArray? {
        val t = label.toString()
        val idx = t.indexOf(':')
        if (idx < 0 || idx+1 >= t.length) return null
        val b64 = t.substring(idx+1).trim()
        return decodeB64OrNull(b64)
    }

    private fun copyToTemp(uri: Uri): File {
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: "picked.bin"
        val dst = File(cacheDir, name)
        contentResolver.openInputStream(uri).use { input ->
            FileOutputStream(dst).use { out ->
                input!!.copyTo(out)
            }
        }
        return dst
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
