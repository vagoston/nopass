package com.example.agoston_vilmos.myapplication;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Vibrator;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.util.SparseArray;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;

import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.google.android.gms.common.util.IOUtils;
import com.google.android.gms.vision.CameraSource;
import com.google.android.gms.vision.Detector;
import com.google.android.gms.vision.barcode.Barcode;
import com.google.android.gms.vision.barcode.BarcodeDetector;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import de.uni_postdam.hpi.jerasure.Encoder;

import static com.android.volley.Request.Method.POST;

public class MainActivity extends AppCompatActivity{

    private String alias = "NoPass";
    private RequestQueue queue;

    String baseURL ="https://s3bd4f4ova.execute-api.eu-west-1.amazonaws.com/dev/";
    long key_size;

    EditText sessionInput;
    SurfaceView cameraPreview;
    BarcodeDetector barcodeDetector;
    CameraSource cameraSource;
    final int RequestCameraPermissionID = 1001;
    SecureRandom random;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        random = new SecureRandom();
        queue = Volley.newRequestQueue(this);
        setContentView(R.layout.activity_main);
        Toolbar toolbar =  findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        Button button = findViewById(R.id.login);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                login();
            }
        });


        cameraPreview = findViewById(R.id.cameraPreview);

        barcodeDetector = new BarcodeDetector.Builder(this)
                .setBarcodeFormats(Barcode.QR_CODE)
                .build();
        cameraSource = new CameraSource
                .Builder(this, barcodeDetector)
                .setRequestedPreviewSize(640, 480)
                .build();
        cameraPreview.getHolder().addCallback(new SurfaceHolder.Callback() {

            @Override
            public void surfaceCreated(SurfaceHolder surfaceHolder) {
                if (ActivityCompat.checkSelfPermission(getApplicationContext(), android.Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                    //Request permission
                    ActivityCompat.requestPermissions(MainActivity.this,
                            new String[]{Manifest.permission.CAMERA},RequestCameraPermissionID);
                    return;
                }
                try {
                    cameraSource.start(cameraPreview.getHolder());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void surfaceChanged(SurfaceHolder surfaceHolder, int i, int i1, int i2) {
            }

            @Override
            public void surfaceDestroyed(SurfaceHolder surfaceHolder) {
                cameraSource.stop();

            }
        });
        barcodeDetector.setProcessor(new Detector.Processor<Barcode>() {

            @Override
            public void release() {
            }

            @Override
            public void receiveDetections(Detector.Detections<Barcode> detections) {
                final SparseArray<Barcode> qrcodes = detections.getDetectedItems();
                if(qrcodes.size() != 0)
                {
                    sessionInput.post(new Runnable() {
                        @Override
                        public void run() {
                            //Create vibrate
                            Vibrator vibrator = (Vibrator)getApplicationContext().getSystemService(Context.VIBRATOR_SERVICE);
                            vibrator.vibrate(1000);
                            sessionInput.setText(qrcodes.valueAt(0).displayValue);
                        }
                    });
                }
            }
        });
        register();
    }



    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        switch (requestCode) {
            case RequestCameraPermissionID: {
                if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    if (ActivityCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                        return;
                    }
                    try {
                        cameraSource.start(cameraPreview.getHolder());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            break;
        }
    }

    private void register() {

        sessionInput = findViewById(R.id.session);
        Button loginButton = findViewById(R.id.login);
        ProgressBar spinner = findViewById(R.id.spinner);

        KeyStore.Entry entry = getOrCreateKeys();
        File f = new File(this.getFilesDir(), "jumpcode");
        String jc;
        if (!f.exists()) {
            jc = String.valueOf(random.nextInt());
            writeJC(jc);
        }
        else {
            jc = readJC();
        }
        final String signature = sign(jc, entry);
        sendRegistrationRequest(readPEM(), signature, jc);
        sessionInput.setVisibility(View.VISIBLE);
        loginButton.setVisibility(View.VISIBLE);
        spinner.setVisibility(View.GONE);
    }

    private KeyStore.Entry getOrCreateKeys() {
        KeyStore.Entry entry;
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            entry = ks.getEntry(this.alias, null);
            if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                KeyGenerator kg = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                kg.init(new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_ENCRYPT |
                                KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setRandomizedEncryptionRequired(false)
                        .setKeySize(128)
                        .build());
                kg.generateKey();
                entry = ks.getEntry(alias, null);
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                writePEM(Base64.encodeToString(kp.getPublic().getEncoded(), Base64.DEFAULT));
//                writeBinaryFile(kp.getPublic().getEncoded(), "key.pub");
                writeBinaryFile(
                        encrypt(
                                kp.getPrivate().getEncoded(),
                                ((KeyStore.SecretKeyEntry) entry)
                                        .getSecretKey()),
                        "key");
                byte[] privateKey = kp.getPrivate().getEncoded();
                createShards(privateKey, entry);
                Log.w("Registration", "New key was generated");
            }
        }
        catch (CertificateException
                | KeyStoreException
                | NoSuchAlgorithmException
                | IOException
                | UnrecoverableEntryException
                | NoSuchProviderException
                | InvalidAlgorithmParameterException
                ex)
        {
            Log.w("Registration", "Could not generate key");
            return null;
        }
        return entry;
    }

    private String sign(String s, KeyStore.Entry entry) {
        String signature;
        try {
            byte[] encryptedKey = readBinaryFile("key");
            byte[] decryptedKey = decrypt(encryptedKey, ((KeyStore.SecretKeyEntry) entry).getSecretKey());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decryptedKey);
            PrivateKey key = keyFactory.generatePrivate(privateKeySpec);
            Signature signer = Signature.getInstance("SHA256withRSA/PSS");
            signer.initSign(key);
            signer.update(s.getBytes());
            signature = Base64.encodeToString(signer.sign(), Base64.DEFAULT);
            }

        catch (NoSuchAlgorithmException |
                InvalidKeyException |
                SignatureException |
                InvalidKeySpecException
                ex){
            Log.e("Register", "was not able to sign", ex);
            return null;
        }
        return signature;
    }

    private void sendRegistrationRequest(final String p, final String s, final String j){

        Map<String,String> parameters = new HashMap<>();
        parameters.put("pk", p);
        parameters.put("signature", s);
        parameters.put("jc", j);
        parameters.put("email", p.substring(50, 55));
        parameters.put("length", String.valueOf(key_size));

        this.queue.add(sendPostRequest("session/register", parameters));
    }

    private void login() {
        Log.d("Login", "clicked");
        EditText input = findViewById(R.id.session);
        String sessionId = input.getText().toString();
        input.setText("");
        KeyStore.Entry entry = getOrCreateKeys();
        String jc = readJC();
        String njc = String.valueOf(random.nextInt());
        sendLoginRequest(sessionId, hash(readPEM()), sign(sessionId, entry), jc, njc);
        writeJC(njc);
    }

    private String hash(String str) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(str.getBytes("UTF-8"));
            return Base64.encodeToString(md.digest(), Base64.NO_WRAP);
        }
        catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            }
        return "";
        }

    private void sendLoginRequest(final String id,
                                  final String pkh,
                                  final String s,
                                  final String ojc,
                                  final String njc) {
        Map<String,String> parameters = new HashMap<>();
        parameters.put("session_id", id);
        parameters.put("pk_hash", pkh);
        parameters.put("signature", s);
        parameters.put("old_jc", ojc);
        parameters.put("new_jc", njc);

        this.queue.add(sendPostRequest("session/login", parameters));
    }

    private void sendUploadShardRequest(String pem,
                                        int i,
                                        String wpk,
                                        String esk,
//                                        String iv,
                                        String encodedShard,
                                        String signature) {
        Map<String,String> parameters = new HashMap<>();
        parameters.put("pk", pem);
        parameters.put("index", String.valueOf(i));
        parameters.put("wpk", wpk);
        parameters.put("esk", esk);
//        parameters.put("iv", iv);
        parameters.put("shard", encodedShard);
        parameters.put("signature", signature);

        this.queue.add(sendPostRequest("restore/upload", parameters));
    }


    private StringRequest sendPostRequest(final String urlParam, final Map<String, String> parameters){
         return new StringRequest(POST, baseURL +urlParam,
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        Log.i(urlParam, "Success");
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                Log.i(urlParam, "Error in request, network error");
            }
        }){
            @Override
            protected Map<String,String> getParams(){
                return parameters;
            }

            @Override
            public Map<String, String> getHeaders() {
                Map<String,String> params = new HashMap<>();
                params.put("Content-Type","application/x-www-form-urlencoded");
                return params;
            }
        };

    }

    private void createShards(byte[] secret, KeyStore.Entry entry) {
//      This could be done without writing files.
        String filename = "key_for_shard";
        File key = new File(this.getFilesDir(), filename);
        try {
            FileOutputStream outputStream = openFileOutput(filename, Context.MODE_PRIVATE);
            outputStream.write(secret);
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Encoder e = new Encoder(3,2,8);
        e.encode(key);
        key_size = key.length();
        key.delete();
//        To restore:
//        Decoder d = new Decoder(key,3,2,8);
//        d.decode(length);
        String pem = readPEM();
//        uploadLength(hash(pem), length, Sign(String.valueOf(length), entry));
        PublicKey[] keys = getWitnesses();
        for (int i = 0 ; i < 5; i++) {
            String shardFileName = filename + "_" + ( i /3 == 0 ?"k0":"m0") +String.valueOf(i % 3 +1);
            String shard = readFile(shardFileName);
            String wpk = Base64.encodeToString(keys[i].getEncoded(), Base64.DEFAULT);
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey sk = kg.generateKey();
                String encryptedShard = Base64.encodeToString(
                        encrypt( shard.getBytes(),
                                sk),
                        Base64.DEFAULT);
                byte[][] encrypted = encrypt( sk.getEncoded(),
                        keys[i]);
                String encryptedsk = Base64.encodeToString(encrypted[0],
                        Base64.DEFAULT);
//                String iv = Base64.encodeToString(encrypted[1],
//                        Base64.DEFAULT);

                String data = pem + String.valueOf(i) + wpk + encryptedsk + encryptedShard;
                String signature = sign(data, entry);
                sendUploadShardRequest(pem, i, wpk, encryptedsk, encryptedShard, signature);
                writeFile(encryptedShard, filename + "i");
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace();
            }

            File fin = new File(this.getFilesDir(), shardFileName);
            fin.delete();
        }
    }

    private byte[][] encrypt(byte[] data, PublicKey key) {
        byte[][] ret = new byte[2][];
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted =  cipher.doFinal(data);
            ret[0] = encrypted;
            //ret[1] = cipher.getIV();
        } catch (InvalidKeyException |
                IllegalBlockSizeException |
                BadPaddingException |
                NoSuchPaddingException |
                NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
        return ret;
    }

    private byte[] encrypt(byte[] data, SecretKey key) {
        byte[] encrypted = {};
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("0000000000000000".getBytes()));
            encrypted =  cipher.doFinal(data);
        } catch (InvalidKeyException |
                IllegalBlockSizeException |
                BadPaddingException |
                NoSuchPaddingException |
                NoSuchAlgorithmException |
                InvalidAlgorithmParameterException e1) {
            e1.printStackTrace();
        }
        return encrypted;
    }

    private byte[] decrypt(byte[] data, SecretKey key) {
        byte[] decrypted = {};
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec("0000000000000000".getBytes()));
            decrypted =  cipher.doFinal(data);
        } catch (InvalidKeyException |
                IllegalBlockSizeException |
                BadPaddingException |
                NoSuchPaddingException |
                NoSuchAlgorithmException |
                InvalidAlgorithmParameterException e1) {
            e1.printStackTrace();
        }
        return decrypted;
    }

    private String readPEM() {
        return readFile("key.pub");
    }

    private String readJC() {
        return readFile("jumpcode");
    }

    private String readFile(String filename) {
        String content = "";
        try {
            content = new String(readBinaryFile(filename), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return content;
    }

    private byte[] readBinaryFile(String filename) {
        byte[] content = {};
        FileInputStream inputStream;
        try  {
            inputStream = openFileInput(filename);
            content = IOUtils.toByteArray(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    private void writeJC(String filecContents){
        writeFile(filecContents, "jumpcode");
    }

    private void writePEM(String filecContents){
        writeFile(filecContents, "key.pub");
    }

    private void writeFile(String fileContents, String filename) {
        writeBinaryFile(fileContents.getBytes(), filename);
    }

    private void writeBinaryFile(byte[] fileContents, String filename) {
        FileOutputStream outputStream;

        try {
            outputStream = openFileOutput(filename, Context.MODE_PRIVATE);
            outputStream.write(fileContents);
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private PublicKey[] getWitnesses() {
        String[] pems= {
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmbQplbLrv8eG7Z3Opt6l\n" +
                        "EfXzmdTLi2xGF1F5qBzHdLFnnZ4uah5Tgydfo0fogSXJiQPw1sl748NllhM5/gNR\n" +
                        "cd+ee5FBwOgn0LyTQb2rUWUQUlOgR2x+T81Z2ZToDcUWXNNibhtKa2ryfwQsoPiS\n" +
                        "uYAup5X8OW796tCV42N42VRoeAxAInhcu43MK72YhjR2NnfhnpKGCgXMAZ2yUmUY\n" +
                        "665XbQponfizbDpuz7HNWUkuosnOowrjVEqAu2eOy0iLdh2TOFA9K8RshCOP87WR\n" +
                        "ZHK/zVC1BUFCFusCArj97xKhrc6xGLLBcV8GQPC0U+lnV5EbjznFbuBgdQOdwF36\n" +
                        "SPFJlioXdo8nHzlX6BfEVXhgEBpQuENYlMLDIxh+oN1r/9j/qQ5c5VreOYUpqJ9L\n" +
                        "JRW/TT75pZkTpx50obJ5L8KH90kCDPZFlhD77fQZG7+ISNI+TXL/ek2DhHPdclKc\n" +
                        "mhLlruxEYy2l0SLa4OowkaasHq+yvDXH2RAiez20Vnuux+hwGH243cf7lfsjuv/j\n" +
                        "Grwtq90l1aCze9G19jYKYPEGEacnT9upa1gagCRCqgxl0z2ayFbwvsyYSDlvx2a6\n" +
                        "OvUSIbrBs/RcNUo1CWiHyJbjgauDn0c7xt/ARzu7NTQpi3ljjUXEupAux5dEcMsZ\n" +
                        "aWcDvsxcQyEv7iHm175icHMCAwEAAQ==",
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAi+k89XqlpQQbazslW49p\n" +
                        "vMshSJdJUP3Q8UDe1pZezsqSQE4wKzzTyTSL+4W/+C6qL/Tc+DhG9ib1iHZsIgVv\n" +
                        "D9rt9z7yBhKDEuH23soQHMXms1b4HXEeifvuOtwJY6UJ6lpfozmQwIYjz5P8iMPp\n" +
                        "wkA5t44UFXm/26faTsb5hEZWYp56zvTFtzt/p74Xw2oLWGypY6V2WI7LYFAksAsX\n" +
                        "P2ZL/bLyB2P5oonxKG5ze1cMs2R1TzSFqA91JcRzObNQ+BMhCTISdyTriODdy78i\n" +
                        "U/YfA+HWtOiuyL32Gjmlh5hDpugkZYyWIrvfS7EfV5EtlkEw3GbVaKt2Yx9QLodA\n" +
                        "DmoICdjFoZmvoQ6euEdCIxhy0UsNTbheYAA6OIUmhKyEC5Te7qNIeKWvFFLKFSX2\n" +
                        "GURLCfakZUPHB977VaOI5yO5hwxCMbks7fSm+5i3sGfF6R9JbV7LF/cM2H4v6pai\n" +
                        "oMvpaOwcC5DdoWUhnrSQ2isk3G4lQbBG0mAUw/VkniGQzvZuwrSxbM25iRDy1N/M\n" +
                        "r/OsvEyWfrlPn4EwjNE7uhHzkdAXTmfrrp5vavwdS0m/DEjTjB8fjo0VOjyi1m9Y\n" +
                        "os3JYUBlsOKXqchI5hlH39DnAI/6uQ+6hMEK24hhxGGzyR+scrv7ODkdz9sHXv/y\n" +
                        "fFtLmLHgu+Qq0clTYWwMkF0CAwEAAQ==",
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn08tffrtA3Jvqml0iI86\n" +
                        "0ctBwc32JHXDQ5fCKqqzzwaMIYMM8jYnhTTSzMTHkY8YDZGBJ8qIm8VeWgoe1x9F\n" +
                        "0cQQNCHo6ItETgz82W9IxuAFbWr58fFNU6Wysn1c+N2HLWRi7e8fwOfT1+cKKJfv\n" +
                        "8N47+4VBgxPKxcac4VCB7TOyHk7mpE/RK92sxh+NEJej01UiMxKiRqwTmGWGvONb\n" +
                        "YYgtGU6GSmyoCmU0B2P1VRS+cMfCIweKYpEG4ebuaUgxcxuqt+IRDYKK2bkfzvxz\n" +
                        "FIpSGoCmmjwwGDQyEzIZu9hfK+Igsq8FiqdkEULl0p/6vr2v8zODVKB2sOKEF9or\n" +
                        "n/Uv1zpl4X2ga3uq7nXRViFhBvHFCxY1o5V5yX45MhMhxlMcwHYUkrZKYOaW0J+r\n" +
                        "6mh0ThxmbQaRejdyuPvBJKkjjeUWgJL2zlTeacHUx6EnLg8te/+QtOT3LmilZWVz\n" +
                        "8RRCxQ9tffEvkqfiFowNhh8oVrzgWA5r7OSMpp2xMiw5ZWtYKKKYQMdf/0qU/ES8\n" +
                        "otJkKdf328MnYt2AhMiCnAhZnISjJkAkwdbqej7oAP8sdL625yhqM/DwrpVouj5Q\n" +
                        "ewFdYLnowHHQifqRuacyLy/p//qK01WMfinlz6iIWxzZEaSn03DPF9LAJJFs5M5y\n" +
                        "5k+XhW5J6huhwSRfW21nyusCAwEAAQ==",
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyzuLF77UsBmGQNWcQNus\n" +
                        "aVi8T47QIo/z52gy/m1SilauKg8kPCoWpGOOwyeGIpCHSUe8a+SqvUI4r+2uDNss\n" +
                        "lKiitY3x7U7abhSKsmyAnZGHHqR+wleHrqLKPArrvWxFS8bte7q0Ag6ikrn8TMue\n" +
                        "SypAk3bU2jTkEK2Zz1PFoha0nBTMktPSki0UjqNT0tESu58imsDR8hPZraJDAMkk\n" +
                        "mjMJyfJwm3rlOqMQqqpmnihqWKXl2yN3xWT56rIloDIaVibTgUgqE497nOrfXFFi\n" +
                        "PoyYnMUiswoZ4Pqsp6SyfWGY5xDljCoLsZKP00ePW5QTjY3CiZzrrsP5pqLsnHFn\n" +
                        "e+VBcX6dQkhrBEjeIGKzltTRjYRRIPSM0u2dkidIWY6wLVXMi8WsH4ziXsv1xU7z\n" +
                        "RwKEPWRScaMRCFl+4xOUfCcWxCdy/I3nZ7dopwF+FLi1sw4RhNnN940JH4FCdI/A\n" +
                        "h2CGqD3z886Z17eO1rMrhRhRM9mN3uylJw57SjBEipBB9dOWHkA4xf87NU6zhTDY\n" +
                        "LW5AZKlIHPGFABQ+g3AUmu4JuSce28BTvAMmQZYl2X83an0B1Al+dowi3L50UCCB\n" +
                        "5+yiSQZfu0a0fQaKKUHSGu+toJJIEdY9MCQk8I63vE5jI0zurvDlP5hDe54qJMlr\n" +
                        "YBUmif6wVU7ot3CntmxgzfECAwEAAQ==",
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwLYCHn8y5XV839YgbL8R\n" +
                        "Vuxmc/3QerA0IVncS/akOoXCQ8c2nKbRLk0OT+/dhQZiZ2Y6MmVwbp1ftJ6zOCjb\n" +
                        "m8hmm7Asv3M1uISP2C3pZa9TAs1lKaQXpqwI2rfrTFMHz92JnIYl1PCK/B13SEpp\n" +
                        "L6pTOx46tr6C16LLcWQCgwqH/+21HR+W+FWiL4IfKVS8qrGs5Fyzi4HCZg5jvo2Q\n" +
                        "z8wZsvu/AvGlbG2gEW879y6D8hDw2BFmgpBhS7GXXOGzMh7BLHhdSMTmmKTyp4Mp\n" +
                        "E3a0ZBvFCiRGLUeEYlCWAB6IFrpBitGF0ovghYiMGtDsOgEo8y+KF2kJMhNZavNt\n" +
                        "+4JFXQMSYvYMkqyef8DFhU84fKM3H1sXxmWlg+NfSUALaSLp+ZXvJUhT8L3ANZIX\n" +
                        "+dV7EFEzy7SJLvMzSPpHRL6ZACt6X57fzLAU5ouUjboBN8aSzIRGbnfzTAQ4lKGl\n" +
                        "N9bnxoXdrYHLbYCu15oq+48uV0ZHkcwn4CDpJabF7+RfEY9GBcUDcAQuYWNNvYYM\n" +
                        "yya68CkBy/u7h/jAbD7qL56dgf/qahRK7WGOq5trp5jWFS+ssQ3EwbHoVC/I1UGN\n" +
                        "AAoPdVubFxKbZrvalcFcGE3EwbCoWB75l+h7JwyUGCLONCPWK0LD0wAEeMa5h0yj\n" +
                        "sTBsvFtQtvSultVczy9Y7r0CAwEAAQ=="
        };
        ArrayList<PublicKey> keys = new ArrayList<>();
        try {
            for (String s : pems) {
                byte[] byteKey = Base64.decode(s.getBytes(), Base64.DEFAULT);
                X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                keys.add(kf.generatePublic(X509publicKey));
            }
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return (keys.toArray(new PublicKey[keys.size()]));
    }
}
