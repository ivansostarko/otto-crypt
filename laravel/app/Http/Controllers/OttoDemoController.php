<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\StreamedResponse;
use IvanSostarko\OttoCrypt\Facades\OttoCrypt as Otto;
use IvanSostarko\OttoCrypt\KeyExchange;

class OttoDemoController extends Controller
{
    public function index()
    {
        // Render the demo blade
        return view('otto-demo');
    }

    public function encryptText(Request $request)
    {
        $request->validate([
            'plaintext' => 'required|string',
        ]);

        $options = $this->extractOptions($request, mode: 'encrypt');
        try {
            [$cipherAndTag, $header] = Otto::encryptString($request->input('plaintext'), $options);
            return back()->with([
                'text_cipher_b64' => base64_encode($cipherAndTag),
                'text_header_b64' => base64_encode($header),
                'active_tab' => 'text',
                'options_mode' => $options['__mode'] ?? 'password',
            ]);
        } catch (\Throwable $e) {
            return back()->withErrors(['text_error' => 'Encrypt error: ' . $e->getMessage()])->withInput();
        }
    }

    public function decryptText(Request $request)
    {
        $request->validate([
            'cipher_b64' => 'required|string',
            'header_b64' => 'required|string',
        ]);

        $options = $this->extractOptions($request, mode: 'decrypt');
        try {
            $cipher = base64_decode($request->input('cipher_b64'), true) ?: '';
            $header = base64_decode($request->input('header_b64'), true) ?: '';
            $plaintext = Otto::decryptString($cipher, $header, $options);
            return back()->with([
                'text_plain_dec' => $plaintext,
                'active_tab' => 'text',
                'options_mode' => $options['__mode'] ?? 'password',
            ]);
        } catch (\Throwable $e) {
            return back()->withErrors(['text_error' => 'Decrypt error: ' . $e->getMessage()])->withInput();
        }
    }

    public function encryptFile(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
        ]);

        $file = $request->file('file');
        $origName = $file->getClientOriginalName();
        $tmpDir = 'otto-demo/' . Str::uuid()->toString();
        $inPath = $file->storeAs($tmpDir, $origName);
        $absIn = storage_path('app/' . $inPath);
        $outName = $origName . '.otto';
        $outPath = storage_path('app/' . $tmpDir . '/' . $outName);

        $options = $this->extractOptions($request, mode: 'encrypt');

        try {
            Otto::encryptFile($absIn, $outPath, $options);
        } catch (\Throwable $e) {
            return back()->withErrors(['file_error' => 'Encrypt error: ' . $e->getMessage()])->withInput();
        }

        return $this->downloadAndCleanup($outPath, $outName, [$absIn, $outPath]);
    }

    public function decryptFile(Request $request)
    {
        $request->validate([
            'encfile' => 'required|file',
        ]);

        $file = $request->file('encfile');
        $origName = $file->getClientOriginalName();
        $tmpDir = 'otto-demo/' . Str::uuid()->toString();
        $inPath = $file->storeAs($tmpDir, $origName);
        $absIn = storage_path('app/' . $inPath);
        $outName = preg_replace('/\.otto$/', '.dec', $origName) ?: ($origName . '.dec');
        $outPath = storage_path('app/' . $tmpDir . '/' . $outName);

        $options = $this->extractOptions($request, mode: 'decrypt');

        try {
            Otto::decryptFile($absIn, $outPath, $options);
        } catch (\Throwable $e) {
            return back()->withErrors(['file_error' => 'Decrypt error: ' . $e->getMessage()])->withInput();
        }

        return $this->downloadAndCleanup($outPath, $outName, [$absIn, $outPath]);
    }

    private function extractOptions(Request $request, string $mode): array
    {
        // Decide between password / X25519 / raw key modes from radio buttons
        $which = $request->input('mode', 'password');
        $opts = [];
        $opts['__mode'] = $which;

        if ($which === 'password') {
            $pw = (string)$request->input('password', '');
            if ($pw === '') throw new \InvalidArgumentException('Password required.');
            $opts['password'] = $pw;
        } elseif ($which === 'x25519') {
            if ($mode === 'encrypt') {
                $rcpt = (string)$request->input('recipient_public', '');
                if ($rcpt === '') throw new \InvalidArgumentException('Recipient public key required.');
                $opts['recipient_public'] = $rcpt;
            } else {
                $sk = (string)$request->input('sender_secret', '');
                if ($sk === '') throw new \InvalidArgumentException('Sender secret key required.');
                $opts['sender_secret'] = $sk;
            }
        } elseif ($which === 'raw') {
            $raw = (string)$request->input('raw_key', '');
            if ($raw === '') throw new \InvalidArgumentException('Raw key (32 bytes) required.');
            // Package will accept base64/hex/raw string
            $opts['raw_key'] = $raw;
        } else {
            throw new \InvalidArgumentException('Unknown mode.');
        }
        return $opts;
    }

    private function downloadAndCleanup(string $absPath, string $downloadName, array $cleanupPaths): StreamedResponse
    {
        return response()->streamDownload(function () use ($absPath, $cleanupPaths) {
            $fp = fopen($absPath, 'rb');
            while (!feof($fp)) {
                echo fread($fp, 8192);
                @ob_flush(); flush();
            }
            fclose($fp);
            // Cleanup temp files/dirs
            foreach ($cleanupPaths as $p) {
                @unlink($p);
            }
        }, $downloadName, [
            'Content-Type' => 'application/octet-stream',
        ]);
    }
}
