package io.jans.jansfidoapp;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.view.GravityCompat;
import androidx.drawerlayout.widget.DrawerLayout;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.snackbar.Snackbar;
import com.google.common.collect.Lists;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;

import duo.labs.webauthn.exceptions.VirgilException;
import duo.labs.webauthn.exceptions.WebAuthnException;
import duo.labs.webauthn.models.AttestationObject;
import duo.labs.webauthn.models.AuthenticatorGetAssertionOptions;
import duo.labs.webauthn.models.AuthenticatorGetAssertionResult;
import duo.labs.webauthn.models.AuthenticatorMakeCredentialOptions;
import duo.labs.webauthn.models.PublicKeyCredentialDescriptor;
import duo.labs.webauthn.models.PublicKeyCredentialSource;
import duo.labs.webauthn.models.RpEntity;
import duo.labs.webauthn.models.UserEntity;
import duo.labs.webauthn.util.CredentialSelector;
import io.jans.jansfidoapp.models.assertion.option.AssertionOptionRequest;
import io.jans.jansfidoapp.models.assertion.option.AssertionOptionResponse;
import io.jans.jansfidoapp.models.assertion.result.AssertionResultRequest;
import io.jans.jansfidoapp.models.attestation.option.AttestationOptionRequest;
import io.jans.jansfidoapp.models.attestation.option.AttestationOptionResponse;
import io.jans.jansfidoapp.models.attestation.result.AttestationResultRequest;
import io.jans.jansfidoapp.retrofit.RetrofitClient;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class MainActivity extends AppCompatActivity
        implements NavigationView.OnNavigationItemSelectedListener {
    private static final String TAG = MainActivity.class.getName();

    private String mToBeSignedMessage;

    // Unique identifier of a key pair
    private static final String KEY_NAME = UUID.randomUUID().toString();
    Authenticator authenticator;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        try {
            authenticator = new Authenticator(MainActivity.this, false, false);
        } catch (VirgilException e) {
            throw new RuntimeException(e);
        }
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @SuppressLint("WrongConstant")
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.addDrawerListener(toggle);
        toggle.syncState();

        NavigationView navigationView = findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);
    }

    @Override
    public void onBackPressed() {
        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
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
    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();

        if (id == R.id.nav_register) {
            if (canAuthenticateWithStrongBiometrics()) {  // Check whether this device can authenticate with biometrics
                Log.i(TAG, "Try registration");
                // Generate keypair and init signature
                Signature signature;
                try {
                    KeyPair keyPair = generateKeyPair(KEY_NAME, true);
                    // Send public key part of key pair to the server, this public key will be used for authentication
                    mToBeSignedMessage = Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.URL_SAFE) +
                            ":" +
                            KEY_NAME +
                            ":" +
                            // Generated by the server to protect against replay attack
                            "12345";

                    signature = initSignature(KEY_NAME);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                // Create biometricPrompt
                showBiometricPrompt(signature, id);
            } else {
                // Cannot use biometric prompt
                Toast.makeText(this, "Cannot use biometric", Toast.LENGTH_SHORT).show();
            }
        } else if (id == R.id.nav_authenticate) {
            if (canAuthenticateWithStrongBiometrics()) {  // Check whether this device can authenticate with biometrics
                Log.i(TAG, "Try authentication");

                // Init signature
                Signature signature;
                try {
                    // Send key name and challenge to the server, this message will be verified with registered public key on the server
                    mToBeSignedMessage = KEY_NAME +
                            ":" +
                            // Generated by the server to protect against replay attack
                            "12345";
                    signature = initSignature(KEY_NAME);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                // Create biometricPrompt
                showBiometricPrompt(signature, id);
            } else {
                // Cannot use biometric prompt
                Toast.makeText(this, "Cannot use biometric", Toast.LENGTH_SHORT).show();
            }
        }

        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }

    private void showBiometricPrompt(Signature signature, int id) {
        BiometricPrompt.AuthenticationCallback authenticationCallback = getAuthenticationCallback(id);
        BiometricPrompt mBiometricPrompt = new BiometricPrompt(this, getMainThreadExecutor(), authenticationCallback);

        // Set prompt info
        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setDescription("Description")
                .setTitle("Title")
                .setSubtitle("Subtitle")
                .setNegativeButtonText("Cancel")
                .build();

        // Show biometric prompt
        if (signature != null) {
            Log.i(TAG, "Show biometric prompt");
            mBiometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(signature));
        }
    }

    private BiometricPrompt.AuthenticationCallback getAuthenticationCallback(int id) {
        // Callback for biometric authentication result
        return new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                Log.e(TAG, "Error code: " + errorCode + "error String: " + errString);
                super.onAuthenticationError(errorCode, errString);
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                Log.i(TAG, "onAuthenticationSucceeded");
                super.onAuthenticationSucceeded(result);
                if (result.getCryptoObject() != null &&
                        result.getCryptoObject().getSignature() != null) {
                    try {
                        Signature signature = result.getCryptoObject().getSignature();
                        signature.update(mToBeSignedMessage.getBytes());
                        String signatureString = Base64.encodeToString(signature.sign(), Base64.URL_SAFE);
                        // Normally, ToBeSignedMessage and Signature are sent to the server and then verified
                        Log.i(TAG, "Message: " + mToBeSignedMessage);
                        Log.i(TAG, "Signature (Base64 Encoded): " + signatureString);
                        Toast.makeText(getApplicationContext(), mToBeSignedMessage + ":" + signatureString, Toast.LENGTH_SHORT).show();
                        if (id == R.id.nav_register) {
                            attestationOption();
                        } else if (id == R.id.nav_authenticate) {
                            assertionOption();
                        }
                    } catch (SignatureException e) {
                        throw new RuntimeException();
                    }
                } else {
                    // Error
                    Toast.makeText(getApplicationContext(), "Something wrong", Toast.LENGTH_SHORT).show();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
            }
        };
    }

    public void authenticate(AssertionOptionResponse responseFromAPI) throws VirgilException, WebAuthnException, NoSuchAlgorithmException, JsonProcessingException {
        AuthenticatorGetAssertionOptions options = new AuthenticatorGetAssertionOptions();
        options.rpId = responseFromAPI.getRpId();
        options.requireUserVerification = false;
        options.requireUserPresence = true;
        options.clientDataHash = generateClientDataHash(responseFromAPI.getChallenge(), "webauthn.get", "https://admin-ui-test.gluu.org");

        List<PublicKeyCredentialDescriptor> allowCredentialDescriptorList = Lists.newArrayList();
        responseFromAPI.getAllowCredentials().stream()
                .forEach(cred -> {

                    Log.d(TAG, cred.getId());
                    PublicKeyCredentialDescriptor publicKeyCredentialDescriptor = new PublicKeyCredentialDescriptor(cred.getType(), decode(cred.getId()), cred.getTransports());
                    allowCredentialDescriptorList.add(publicKeyCredentialDescriptor);
                });

        options.allowCredentialDescriptorList = allowCredentialDescriptorList;


        AuthenticatorGetAssertionResult assertionObject = authenticator.getAssertion(options, new CredentialSelector() {
            @Override
            public PublicKeyCredentialSource selectFrom(List<PublicKeyCredentialSource> credentialList) {
                return credentialList.get(0);
            }
        });

        AssertionResultRequest assertionResultRequest = new AssertionResultRequest();
        assertionResultRequest.setId(urlEncodeToString(assertionObject.selectedCredentialId).replace("\n", ""));
        assertionResultRequest.setType("public-key");
        assertionResultRequest.setRawId(urlEncodeToString(assertionObject.selectedCredentialId).replace("\n", ""));
        io.jans.jansfidoapp.models.assertion.result.Response response = new io.jans.jansfidoapp.models.assertion.result.Response();
        response.setClientDataJSON(generateClientDataJSON(responseFromAPI.getChallenge(), "webauthn.get", "https://admin-ui-test.gluu.org"));
        response.setAuthenticatorData(urlEncodeToString(assertionObject.authenticatorData).replace("\n", ""));
        response.setSignature(urlEncodeToString(assertionObject.signature).replace("\n", ""));
        assertionResultRequest.setResponse(response);
        assertionResult(assertionResultRequest);
    }

    public void register(AttestationOptionResponse responseFromAPI) throws VirgilException, WebAuthnException, NoSuchAlgorithmException, JsonProcessingException {
        AuthenticatorMakeCredentialOptions options = new AuthenticatorMakeCredentialOptions();
        options.rpEntity = new RpEntity();
        options.rpEntity.id = responseFromAPI.getRp().getId();
        options.rpEntity.name = responseFromAPI.getRp().getName();

        options.userEntity = new UserEntity();
        options.userEntity.id = responseFromAPI.getUser().getId().getBytes();//"vScQ9Aec2Z8RKNvfZhpg375RWVIN1QMf8x_q9houJnc".getBytes();
        options.userEntity.name = responseFromAPI.getUser().getName();//"admin";
        options.userEntity.displayName = responseFromAPI.getUser().getDisplayName();//"admin";
        options.clientDataHash = generateClientDataHash(responseFromAPI.getChallenge(), "webauthn.create", "https://admin-ui-test.gluu.org");

        options.requireResidentKey = false;
        options.requireUserPresence = true;
        options.requireUserVerification = false;
        options.excludeCredentialDescriptorList = Lists.newArrayList();

        List<Pair<String, Long>> credTypesAndPubKeyAlgs = new ArrayList<>();
        Pair<String, Long> pair = new Pair<>("public-key", -7L);
        credTypesAndPubKeyAlgs.add(pair);
        options.credTypesAndPubKeyAlgs = credTypesAndPubKeyAlgs;
        AttestationObject attestationObject = authenticator.makeCredential(options);
        byte[] attestationObjectBytes = attestationObject.asCBOR();
        Log.d(TAG + "attestationObjectBytes :", urlEncodeToString(attestationObjectBytes));
        Log.d(TAG, urlEncodeToString(attestationObject.getCredentialId()).replace("\n", ""));
        AttestationResultRequest attestationResultRequest = new AttestationResultRequest();
        attestationResultRequest.setId(urlEncodeToString(attestationObject.getCredentialId()).replace("\n", ""));
        attestationResultRequest.setType("public-key");

        io.jans.jansfidoapp.models.attestation.result.Response response = new io.jans.jansfidoapp.models.attestation.result.Response();
        response.setAttestationObject(urlEncodeToString(attestationObjectBytes).replace("\n", ""));

        response.setClientDataJSON(generateClientDataJSON(responseFromAPI.getChallenge(), "webauthn.create", "https://admin-ui-test.gluu.org"));
        attestationResultRequest.setResponse(response);
        attestationResult(attestationResultRequest);
        Toast.makeText(getApplicationContext(), "attestationObjectBytes : " + attestationObjectBytes.toString(), Toast.LENGTH_SHORT).show();
    }

    public String urlEncodeToString(byte[] src) {
        return Base64.encodeToString(src, Base64.URL_SAFE);
    }

    public byte[] decode(String src) {
        return Base64.decode(src, Base64.URL_SAFE);
    }

    public void assertionOption() {
        AssertionOptionRequest req = new AssertionOptionRequest();
        req.setUsername("admin");

        Call<AssertionOptionResponse> call = RetrofitClient.getInstance("https://admin-ui-test.gluu.org")
                .getAPIInterface().assertionOption(req, "https://admin-ui-test.gluu.org/jans-fido2/restv1/assertion/options");

        call.enqueue(new Callback<AssertionOptionResponse>() {
            @Override
            public void onResponse(Call<AssertionOptionResponse> call, Response<AssertionOptionResponse> response) {

                AssertionOptionResponse responseFromAPI = response.body();

                if (response.code() == 200 || response.code() == 201) {
                    if (responseFromAPI.getChallenge() != null) {
                        try {
                            authenticate(responseFromAPI);
                        } catch (VirgilException e) {
                            throw new RuntimeException(e);
                        } catch (WebAuthnException e) {
                            throw new RuntimeException(e);
                        } catch (NoSuchAlgorithmException e) {
                            throw new RuntimeException(e);
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                    }
                } else {
                    //return null;
                }
            }

            @Override
            public void onFailure(Call<AssertionOptionResponse> call, Throwable t) {
                Log.e(TAG, "Inside doDCR :: onFailure :: " + t.getMessage());
            }
        });
    }

    public void assertionResult(AssertionResultRequest assertionResultRequest) {
        Call<Map> call = RetrofitClient.getInstance("https://admin-ui-test.gluu.org")
                .getAPIInterface().assertionResult(assertionResultRequest,
                        "https://admin-ui-test.gluu.org/jans-fido2/restv1/assertion/result");
        call.enqueue(new Callback<Map>() {
            @Override
            public void onResponse(Call<Map> call, Response<Map> response) {
                Map responseFromAPI = response.body();
                Log.d(TAG, response.message());
                if (response.code() == 200 || response.code() == 201) {
                    Log.d(TAG, responseFromAPI.toString());
                } else {
                    //return null;
                }
            }

            @Override
            public void onFailure(Call<Map> call, Throwable t) {
                Log.e(TAG, "Inside doDCR :: onFailure :: " + t.getMessage());

            }
        });
    }

    public void attestationOption() {
        AttestationOptionRequest req = new AttestationOptionRequest();
        req.setAttestation("none");
        req.setUsername("admin");
        req.setDisplayName("admin");
        Call<AttestationOptionResponse> call = RetrofitClient.getInstance("https://admin-ui-test.gluu.org")
                .getAPIInterface().attestationOption(req, "https://admin-ui-test.gluu.org/jans-fido2/restv1/attestation/options");

        call.enqueue(new Callback<AttestationOptionResponse>() {
            @Override
            public void onResponse(Call<AttestationOptionResponse> call, Response<AttestationOptionResponse> response) {

                AttestationOptionResponse responseFromAPI = response.body();
                if (response.code() == 200 || response.code() == 201) {
                    if (responseFromAPI.getChallenge() != null) {
                        try {
                            register(responseFromAPI);
                        } catch (VirgilException e) {
                            throw new RuntimeException(e);
                        } catch (WebAuthnException e) {
                            throw new RuntimeException(e);
                        } catch (NoSuchAlgorithmException e) {
                            throw new RuntimeException(e);
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                    }
                } else {
                    //return null;
                }
            }

            @Override
            public void onFailure(Call<AttestationOptionResponse> call, Throwable t) {
                Log.e(TAG, "Inside doDCR :: onFailure :: " + t.getMessage());

            }
        });
    }

    public void attestationResult(AttestationResultRequest attestationResultRequest) {
        Log.d(TAG, "1============================================================");
        Call<Map> call = RetrofitClient.getInstance("https://admin-ui-test.gluu.org")
                .getAPIInterface().attestationResult(attestationResultRequest,
                        "https://admin-ui-test.gluu.org/jans-fido2/restv1/attestation/result");
        Log.d(TAG, "2============================================================");
        call.enqueue(new Callback<Map>() {
            @Override
            public void onResponse(Call<Map> call, Response<Map> response) {
                Log.d(TAG, "3============================================================");
                Map responseFromAPI = response.body();
                Log.d(TAG, "4============================================================");
                Log.d(TAG, response.message());
                if (response.code() == 200 || response.code() == 201) {
                    Log.d(TAG, "5============================================================");
                    Log.d(TAG, responseFromAPI.toString());
                    Log.d(TAG, "6============================================================");
                } else {
                    //return null;
                }
            }

            @Override
            public void onFailure(Call<Map> call, Throwable t) {
                Log.e(TAG, "Inside doDCR :: onFailure :: " + t.getMessage());

            }
        });
    }

    public String generateClientDataJSON(String challenge, String type, String origin) {


        // Convert clientDataJson to JSON string
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode clientData = objectMapper.createObjectNode();
        clientData.put("type", type);
        clientData.put("challenge", challenge);
        clientData.put("origin", origin);
        Log.d(TAG + "clientData.toString()", clientData.toString());
        String clientDataJSON = urlEncodeToString(clientData.toString().getBytes(StandardCharsets.UTF_8));
        Log.d(TAG + "clientDataJSON", clientDataJSON.replace("\n", ""));
        return clientDataJSON.replace("\n", "");
    }

    public byte[] generateClientDataHash(String challenge, String type, String origin) throws JsonProcessingException, NoSuchAlgorithmException {
                // Convert clientDataJson to JSON string
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode clientData = objectMapper.createObjectNode();
        clientData.put("type", type);
        clientData.put("challenge", challenge);
        clientData.put("origin", origin);


        objectMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        String serializedClientData = objectMapper.writeValueAsString(clientData);

        // Calculate SHA-256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(serializedClientData.getBytes(StandardCharsets.UTF_8));
    }

    private KeyPair generateKeyPair(String keyName, boolean invalidatedByBiometricEnrollment) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                // Require the user to authenticate with a biometric to authorize every use of the key
                .setUserAuthenticationRequired(true);

        // Generated keys will be invalidated if the biometric templates are added more to user device
        if (Build.VERSION.SDK_INT >= 24) {
            builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);
        }

        keyPairGenerator.initialize(builder.build());

        return keyPairGenerator.generateKeyPair();
    }

    @Nullable
    private KeyPair getKeyPair(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyName)) {
            // Get public key
            PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            // Return a key pair
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    @Nullable
    private Signature initSignature(String keyName) throws Exception {
        KeyPair keyPair = getKeyPair(keyName);

        if (keyPair != null) {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            return signature;
        }
        return null;
    }

    private Executor getMainThreadExecutor() {
        return new MainThreadExecutor();
    }

    private static class MainThreadExecutor implements Executor {
        private final Handler handler = new Handler(Looper.getMainLooper());

        @Override
        public void execute(@NonNull Runnable r) {
            handler.post(r);
        }
    }

    /**
     * Indicate whether this device can authenticate the user with strong biometrics
     *
     * @return true if there are any available strong biometric sensors and biometrics are enrolled on the device, if not, return false
     */
    private boolean canAuthenticateWithStrongBiometrics() {
        return BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS;
    }
}
