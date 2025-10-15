using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using IvanSostarko.OttoCrypt;

namespace OttoCrypt.Demo.Controllers
{
    public class OttoDemoController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult EncryptText(string plaintext, string mode, string? password, string? recipient_public, string? raw_key)
        {
            try
            {
                var opts = ParseOptions(mode, "encrypt", password, null, recipient_public, raw_key);
                var otto = new OttoCrypt();
                var (cipher, header) = otto.EncryptString(Encoding.UTF8.GetBytes(plaintext ?? string.Empty), opts);
                ViewBag.TextCipherB64 = Convert.ToBase64String(cipher);
                ViewBag.TextHeaderB64 = Convert.ToBase64String(header);
                ViewBag.ActiveTab = "text";
                return View("Index");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("text_error", "Encrypt error: " + ex.Message);
                return View("Index");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult DecryptText(string cipher_b64, string header_b64, string mode, string? password, string? sender_secret, string? raw_key)
        {
            try
            {
                var opts = ParseOptions(mode, "decrypt", password, sender_secret, null, raw_key);
                var otto = new OttoCrypt();
                var cipher = Convert.FromBase64String(cipher_b64 ?? "");
                var header = Convert.FromBase64String(header_b64 ?? "");
                var plain = otto.DecryptString(cipher, header, opts);
                ViewBag.TextPlainDec = Encoding.UTF8.GetString(plain);
                ViewBag.ActiveTab = "text";
                return View("Index");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("text_error", "Decrypt error: " + ex.Message);
                return View("Index");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EncryptFile(IFormFile file, string mode, string? password, string? recipient_public, string? raw_key)
        {
            if (file == null || file.Length == 0)
            {
                ModelState.AddModelError("file_error", "No file selected.");
                return View("Index");
            }

            var tempDir = Path.Combine(Path.GetTempPath(), "otto-demo");
            Directory.CreateDirectory(tempDir);
            var inPath = Path.Combine(tempDir, Guid.NewGuid().ToString() + "_" + file.FileName);
            var outName = file.FileName + ".otto";
            var outPath = Path.Combine(tempDir, Guid.NewGuid().ToString() + "_" + outName);

            try
            {
                await using (var fs = System.IO.File.Create(inPath))
                {
                    await file.CopyToAsync(fs);
                }
                var opts = ParseOptions(mode, "encrypt", password, null, recipient_public, raw_key);
                var otto = new OttoCrypt();
                otto.EncryptFile(inPath, outPath, opts);

                var bytes = await System.IO.File.ReadAllBytesAsync(outPath);
                System.IO.File.Delete(inPath);
                System.IO.File.Delete(outPath);
                return File(bytes, "application/octet-stream", outName);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("file_error", "Encrypt error: " + ex.Message);
                return View("Index");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DecryptFile(IFormFile encfile, string mode, string? password, string? sender_secret, string? raw_key)
        {
            if (encfile == null || encfile.Length == 0)
            {
                ModelState.AddModelError("file_error", "No file selected.");
                return View("Index");
            }

            var tempDir = Path.Combine(Path.GetTempPath(), "otto-demo");
            Directory.CreateDirectory(tempDir);
            var inPath = Path.Combine(tempDir, Guid.NewGuid().ToString() + "_" + encfile.FileName);
            var baseName = encfile.FileName.EndsWith(".otto", StringComparison.OrdinalIgnoreCase)
                ? encfile.FileName.Substring(0, encfile.FileName.Length - 5)
                : encfile.FileName;
            var outName = baseName + ".dec";
            var outPath = Path.Combine(tempDir, Guid.NewGuid().ToString() + "_" + outName);

            try
            {
                await using (var fs = System.IO.File.Create(inPath))
                {
                    await encfile.CopyToAsync(fs);
                }
                var opts = ParseOptions(mode, "decrypt", password, sender_secret, null, raw_key);
                var otto = new OttoCrypt();
                otto.DecryptFile(inPath, outPath, opts);

                var bytes = await System.IO.File.ReadAllBytesAsync(outPath);
                System.IO.File.Delete(inPath);
                System.IO.File.Delete(outPath);
                return File(bytes, "application/octet-stream", outName);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("file_error", "Decrypt error: " + ex.Message);
                return View("Index");
            }
        }

        [HttpGet]
        public IActionResult Keys()
        {
            try
            {
                var (secret, pub) = KeyExchange.GenerateKeypair();
                return Json(new {
                    secret_base64 = Convert.ToBase64String(secret),
                    public_base64 = Convert.ToBase64String(pub),
                    secret_hex = Convert.ToHexString(secret).ToLowerInvariant(),
                    public_hex = Convert.ToHexString(pub).ToLowerInvariant()
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        private static Options ParseOptions(string mode, string op, string? password, string? sender_secret, string? recipient_public, string? raw_key)
        {
            mode = mode ?? "password";
            if (mode == "password")
            {
                if (string.IsNullOrEmpty(password)) throw new ArgumentException("Password required");
                return new Options { Password = password };
            }
            if (mode == "x25519")
            {
                if (op == "encrypt")
                {
                    if (string.IsNullOrEmpty(recipient_public)) throw new ArgumentException("Recipient public key required");
                    return new Options { RecipientPublic = recipient_public };
                }
                else
                {
                    if (string.IsNullOrEmpty(sender_secret)) throw new ArgumentException("Sender secret key required");
                    return new Options { SenderSecret = sender_secret };
                }
            }
            if (mode == "raw")
            {
                if (string.IsNullOrEmpty(raw_key)) throw new ArgumentException("Raw key required");
                return new Options { RawKey = raw_key };
            }
            throw new ArgumentException("Unknown mode");
        }
    }
}
