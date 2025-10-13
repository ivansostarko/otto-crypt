package com.ivansostarko.ottocrypt.demo;

import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import com.ivansostarko.ottocrypt.OttoCrypt;
import java.nio.charset.StandardCharsets;

public class TextFragment extends Fragment {
    @Nullable @Override public View onCreateView(@NonNull LayoutInflater inf, @Nullable ViewGroup parent, @Nullable Bundle st) {
        View v = inf.inflate(R.layout.fragment_text, parent, false);
        RadioGroup modes = v.findViewById(R.id.modeGroupText);
        EditText etPw = v.findViewById(R.id.etPasswordT);
        EditText etRcpt = v.findViewById(R.id.etRecipientPubT);
        EditText etRaw = v.findViewById(R.id.etRawKeyT);
        EditText etPlain = v.findViewById(R.id.etPlaintext);
        EditText etCipher = v.findViewById(R.id.etCipherB64);
        EditText etHeader = v.findViewById(R.id.etHeaderB64);
        Button btnEnc = v.findViewById(R.id.btnEncryptText);
        RadioGroup modesD = v.findViewById(R.id.modeGroupDecText);
        EditText etPwD = v.findViewById(R.id.etPasswordTD);
        EditText etSkD = v.findViewById(R.id.etSenderSecretTD);
        EditText etRawD = v.findViewById(R.id.etRawKeyTD);
        Button btnDec = v.findViewById(R.id.btnDecryptText);
        TextView tvOut = v.findViewById(R.id.tvPlainOut);

        modes.setOnCheckedChangeListener((g, id) -> {
            etPw.setVisibility(id == R.id.rbPasswordT ? View.VISIBLE : View.GONE);
            etRcpt.setVisibility(id == R.id.rbX25519T ? View.VISIBLE : View.GONE);
            etRaw.setVisibility(id == R.id.rbRawT ? View.VISIBLE : View.GONE);
        });
        modesD.setOnCheckedChangeListener((g, id) -> {
            etPwD.setVisibility(id == R.id.rbPasswordTD ? View.VISIBLE : View.GONE);
            etSkD.setVisibility(id == R.id.rbX25519TD ? View.VISIBLE : View.GONE);
            etRawD.setVisibility(id == R.id.rbRawTD ? View.VISIBLE : View.GONE);
        });

        btnEnc.setOnClickListener(v1 -> {
            try {
                OttoCrypt o = new OttoCrypt();
                OttoCrypt.Options opt = new OttoCrypt.Options();
                int sel = modes.getCheckedRadioButtonId();
                if (sel == R.id.rbPasswordT) {
                    opt.password = etPw.getText().toString();
                    if (TextUtils.isEmpty(opt.password)) throw new IllegalArgumentException("Password required");
                } else if (sel == R.id.rbX25519T) {
                    opt.recipientPublic = etRcpt.getText().toString();
                } else {
                    opt.rawKey = etRaw.getText().toString();
                }
                OttoCrypt.EncResult r = o.encryptString(etPlain.getText().toString().getBytes(StandardCharsets.UTF_8), opt);
                etCipher.setText(Base64.encodeToString(r.cipherAndTag, Base64.NO_WRAP));
                etHeader.setText(Base64.encodeToString(r.header, Base64.NO_WRAP));
                Toast.makeText(getContext(), "Encrypted", Toast.LENGTH_SHORT).show();
            } catch (Exception ex) {
                Toast.makeText(getContext(), "Error: " + ex.getMessage(), Toast.LENGTH_LONG).show();
            }
        });

        btnDec.setOnClickListener(v12 -> {
            try {
                OttoCrypt o = new OttoCrypt();
                OttoCrypt.Options opt = new OttoCrypt.Options();
                int sel = modesD.getCheckedRadioButtonId();
                if (sel == R.id.rbPasswordTD) {
                    opt.password = etPwD.getText().toString();
                    if (TextUtils.isEmpty(opt.password)) throw new IllegalArgumentException("Password required");
                } else if (sel == R.id.rbX25519TD) {
                    opt.senderSecret = etSkD.getText().toString();
                } else {
                    opt.rawKey = etRawD.getText().toString();
                }
                byte[] cipher = Base64.decode(etCipher.getText().toString().trim(), Base64.NO_WRAP);
                byte[] header = Base64.decode(etHeader.getText().toString().trim(), Base64.NO_WRAP);
                byte[] plain = o.decryptString(cipher, header, opt);
                tvOut.setText(new String(plain, StandardCharsets.UTF_8));
                Toast.makeText(getContext(), "Decrypted", Toast.LENGTH_SHORT).show();
            } catch (Exception ex) {
                Toast.makeText(getContext(), "Error: " + ex.getMessage(), Toast.LENGTH_LONG).show();
            }
        });

        return v;
    }
}
