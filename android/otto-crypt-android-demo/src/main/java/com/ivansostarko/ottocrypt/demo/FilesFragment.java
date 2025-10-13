package com.ivansostarko.ottocrypt.demo;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import com.ivansostarko.ottocrypt.OttoCrypt;
import java.io.*;

public class FilesFragment extends Fragment {
    private Uri inputUri;
    private Uri outputUri;

    private ActivityResultLauncher<String[]> pickInputLauncher;
    private ActivityResultLauncher<Intent> createOutputLauncher;

    @Override public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        pickInputLauncher = registerForActivityResult(
                new ActivityResultContracts.OpenDocument(),
                uri -> {
                    if (uri != null) {
                        requireContext().getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                        inputUri = uri;
                        TextView tv = getView().findViewById(R.id.tvInput);
                        tv.setText(uri.toString());
                    }
                }
        );
        createOutputLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getData() != null) {
                        Uri uri = result.getData().getData();
                        if (uri != null) {
                            outputUri = uri;
                            TextView tv = getView().findViewById(R.id.tvOutput);
                            tv.setText(uri.toString());
                        }
                    }
                }
        );
    }

    @Nullable @Override public View onCreateView(@NonNull LayoutInflater inf, @Nullable ViewGroup parent, @Nullable Bundle st) {
        View v = inf.inflate(R.layout.fragment_files, parent, false);
        RadioGroup modes = v.findViewById(R.id.modeGroupFile);
        EditText etPw = v.findViewById(R.id.etPasswordF);
        EditText etRcpt = v.findViewById(R.id.etRecipientPubF);
        EditText etRaw = v.findViewById(R.id.etRawKeyF);
        EditText etSk = v.findViewById(R.id.etSenderSecretF);
        RadioGroup encDec = v.findViewById(R.id.modeEncDec);
        Button btnPick = v.findViewById(R.id.btnPickInput);
        Button btnChooseOut = v.findViewById(R.id.btnChooseOutput);
        Button btnRun = v.findViewById(R.id.btnRun);
        TextView tvStatus = v.findViewById(R.id.tvStatus);

        modes.setOnCheckedChangeListener((g, id) -> {
            etPw.setVisibility(id == R.id.rbPasswordF ? View.VISIBLE : View.GONE);
            etRcpt.setVisibility(id == R.id.rbX25519F ? View.VISIBLE : View.GONE);
            etRaw.setVisibility(id == R.id.rbRawF ? View.VISIBLE : View.GONE);
        });
        encDec.setOnCheckedChangeListener((g, id) -> {
            etSk.setVisibility(id == R.id.rbDecrypt ? View.VISIBLE : View.GONE);
        });

        btnPick.setOnClickListener(x -> pickInputLauncher.launch(new String[]{"*/*"}));
        btnChooseOut.setOnClickListener(x -> {
            boolean encrypt = (encDec.getCheckedRadioButtonId() == R.id.rbEncrypt);
            String suggested = encrypt ? "output.otto" : "output.dec";
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, suggested);
            createOutputLauncher.launch(i);
        });

        btnRun.setOnClickListener(x -> {
            if (inputUri == null || outputUri == null) {
                Toast.makeText(getContext(), "Pick input and output first", Toast.LENGTH_SHORT).show();
                return;
            }
            OttoCrypt.Options opt = new OttoCrypt.Options();
            int sel = modes.getCheckedRadioButtonId();
            if (sel == R.id.rbPasswordF) {
                opt.password = etPw.getText().toString();
                if (TextUtils.isEmpty(opt.password)) { Toast.makeText(getContext(),"Password required",Toast.LENGTH_SHORT).show(); return; }
            } else if (sel == R.id.rbX25519F) {
                if (encDec.getCheckedRadioButtonId() == R.id.rbEncrypt) {
                    opt.recipientPublic = etRcpt.getText().toString();
                } else {
                    opt.senderSecret = etSk.getText().toString();
                }
            } else {
                opt.rawKey = etRaw.getText().toString();
            }
            boolean encrypt = (encDec.getCheckedRadioButtonId() == R.id.rbEncrypt);
            tvStatus.setText("Working...");
            new Thread(() -> {
                try {
                    Context ctx = requireContext().getApplicationContext();
                    File tmpIn = File.createTempFile("otto_in", ".bin", ctx.getCacheDir());
                    File tmpOut = File.createTempFile("otto_out", ".bin", ctx.getCacheDir());
                    try (InputStream is = ctx.getContentResolver().openInputStream(inputUri);
                         OutputStream os = new FileOutputStream(tmpIn)) { copy(is, os); }
                    OttoCrypt o = new OttoCrypt();
                    if (encrypt) o.encryptFile(tmpIn.getAbsolutePath(), tmpOut.getAbsolutePath(), opt);
                    else o.decryptFile(tmpIn.getAbsolutePath(), tmpOut.getAbsolutePath(), opt);
                    try (InputStream is2 = new FileInputStream(tmpOut);
                         OutputStream os2 = ctx.getContentResolver().openOutputStream(outputUri, "w")) { copy(is2, os2); }
                    tmpIn.delete(); tmpOut.delete();
                    requireActivity().runOnUiThread(() -> { tvStatus.setText("Done"); Toast.makeText(getContext(),"Done",Toast.LENGTH_SHORT).show(); });
                } catch (Exception ex) {
                    requireActivity().runOnUiThread(() -> { tvStatus.setText("Error: " + ex.getMessage()); Toast.makeText(getContext(),"Error: "+ex.getMessage(),Toast.LENGTH_LONG).show(); });
                }
            }).start();
        });

        return v;
    }

    private static void copy(InputStream is, OutputStream os) throws IOException {
        byte[] buf = new byte[8192]; int r;
        while ((r = is.read(buf)) != -1) os.write(buf,0,r);
    }
}
