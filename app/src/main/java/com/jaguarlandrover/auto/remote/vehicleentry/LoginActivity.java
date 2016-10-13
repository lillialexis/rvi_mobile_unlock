package com.jaguarlandrover.auto.remote.vehicleentry;

import android.app.AlertDialog;
import android.content.*;
import android.net.Uri;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import com.jaguarlandrover.pki.PKICertificateResponse;
import com.jaguarlandrover.pki.PKICertificateSigningRequestRequest;
import com.jaguarlandrover.pki.PKIManager;
import com.jaguarlandrover.pki.PKIServerResponse;
import com.jaguarlandrover.pki.PKITokenVerificationRequest;
import com.jaguarlandrover.rvi.RVILocalNode;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Calendar;

import rx.Observer;
import rx.android.schedulers.AndroidSchedulers;
import rx.schedulers.Schedulers;


public class LoginActivity extends ActionBarActivity implements LoginActivityFragment.LoginFragmentButtonListener{

    private static final String TAG = "UnlockDemo/LoginActvty_";

    private BluetoothRangingService mBluetoothRangingService      = null;
    private LoginActivityFragment   mLoginActivityFragment        = null;
    private boolean                 mBluetoothRangingServiceBound = false;

    private final static String X509_PRINCIPAL_PATTERN = "CN=%s, O=Genivi, OU=%s, EMAILADDRESS=%s";
    private final static String X509_ORG_UNIT          = "Android Unlock App";
    private final static String RVI_DOMAIN             = "genivi.org";

    private final static String DEFAULT_PROVISIONING_SERVER_CSR_URL          = "/csr";
    private final static String DEFAULT_PROVISIONING_SERVER_VERIFICATION_URL = "/verification";


    private boolean mBluetoothRangingServiceConnected = false;
    private boolean mAllValidCertsAcquired            = false;
    private boolean mValidatingToken                  = false;

    private final static boolean BLUETOOTH_RANGING_SERVICE_ENABLED = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        RVILocalNode.start(this, RVI_DOMAIN);

        setContentView(R.layout.activity_login2);
        handleExtra(getIntent());

        mLoginActivityFragment = (LoginActivityFragment) getFragmentManager().findFragmentById(R.id.fragmentlogin);

        mLoginActivityFragment.setVerifyButtonEnabled(true);

        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
        String provisioningServerUrl = "http://" + preferences.getString("pref_provisioning_server_url", "38.129.64.40") + ":" + preferences.getString("pref_provisioning_server_port", "8000");

        mBluetoothRangingServiceConnected = !BLUETOOTH_RANGING_SERVICE_ENABLED;

        Intent intent = getIntent();
        if (Intent.ACTION_VIEW.equals(intent.getAction())) {
            Uri uri = intent.getData();
            String token  = uri.getQueryParameter("token");
            String certId = uri.getQueryParameter("certificate_id");

            if (token != null && certId != null) {
                RVILocalNode.removeAllCredentials(this);

                mLoginActivityFragment.setStatusTextText("Validating email...");
                mLoginActivityFragment.setVerifyButtonEnabled(false);

                mValidatingToken = true;

                PKITokenVerificationRequest request = new PKITokenVerificationRequest(token, certId);

                Log.d(TAG, "Sending token verification request: " + request.toString());

                PKIManager.sendTokenVerificationRequest(this, mProvisioningServerListener, provisioningServerUrl, DEFAULT_PROVISIONING_SERVER_VERIFICATION_URL, request);
            }
        }

        if (!mValidatingToken) {
            if (PKIManager.hasValidSignedDeviceCert(this) && PKIManager.hasValidSignedServerCert(this)) {
                mLoginActivityFragment.hideControls(true);
                mLoginActivityFragment.setStatusTextText("Loading...");

                mAllValidCertsAcquired = true;

                setUpRviAndConnectToServer(PKIManager.getServerKeyStore(this), PKIManager.getDeviceKeyStore(this), null, null);
                launchLockActivityWhenReady();

            } else if (PKIManager.hasValidSignedDeviceCert(this)) {
                mLoginActivityFragment.setStatusTextText("Resend email");
                mLoginActivityFragment.setStatusTextText("Please check your email account and click the 'Verify' link.");

            } else {
                mLoginActivityFragment.setStatusTextText("The RVI Unlock Demo needs to verify your email address.");

            }
        }

        if (BLUETOOTH_RANGING_SERVICE_ENABLED)
            doBindService();
    }

    private PKIManager.ProvisioningServerListener mProvisioningServerListener = new PKIManager.ProvisioningServerListener() {
        @Override
        public void managerDidReceiveResponseFromServer(PKIServerResponse response) {
            if (response.getStatus() == PKIServerResponse.Status.VERIFICATION_NEEDED) {
                mValidatingToken = true;
                mAllValidCertsAcquired = false;

                mLoginActivityFragment.setStatusTextText("Resend email");
                mLoginActivityFragment.setStatusTextText("Please check your email account and click the 'Verify' link.");

            } else if (response.getStatus() == PKIServerResponse.Status.CERTIFICATE_RESPONSE) {
                Log.d(TAG, "Got server stuff, trying to connect");

                mValidatingToken = false;
                mAllValidCertsAcquired = true;

                PKICertificateResponse certificateResponse = (PKICertificateResponse) response;

                setUpRviAndConnectToServer(certificateResponse.getServerKeyStore(), certificateResponse.getDeviceKeyStore(), null, certificateResponse.getJwtCredentials());
                launchLockActivityWhenReady();
            } else if (response.getStatus() == PKIServerResponse.Status.ERROR) {

                if (!mValidatingToken) {
                    mLoginActivityFragment.setVerifyButtonEnabled(true);

                    mLoginActivityFragment.setStatusTextText("Resend");
                    mLoginActivityFragment.setStatusTextText("An error occurred when sending your certificate signing request to the server.");
                } else {
                    mLoginActivityFragment.setVerifyButtonEnabled(true);

                    mLoginActivityFragment.setStatusTextText("Resend email");
                    mLoginActivityFragment.setStatusTextText("An error occurred when verifying your email. Please click the email link again or the button to send a new email.");
                }
            }
        }
    };

    private PKIManager.CertificateSigningRequestGeneratorListener mCertificateSigningRequestGeneratorListener = new PKIManager.CertificateSigningRequestGeneratorListener() {
        @Override
        public void generateCertificateSigningRequestSucceeded(String certificateSigningRequest) {
            Log.d(TAG, "Sending certificate signing request to server.");

            mLoginActivityFragment.setVerifyButtonEnabled(true);
            mLoginActivityFragment.setStatusTextText("Resend email");
            mLoginActivityFragment.setStatusTextText("Please check your email account and click the link.");

            SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(LoginActivity.this);
            String provisioningServerUrl = "http://" + preferences.getString("pref_provisioning_server_url", "38.129.64.40") + ":" + preferences.getString("pref_provisioning_server_port", "8000");

            PKICertificateSigningRequestRequest request = new PKICertificateSigningRequestRequest(certificateSigningRequest);

            PKIManager.sendCertificateSigningRequest(LoginActivity.this, mProvisioningServerListener, provisioningServerUrl, DEFAULT_PROVISIONING_SERVER_CSR_URL, request);
        }

        @Override
        public void generateCertificateSigningRequestFailed(Throwable reason) {
            mLoginActivityFragment.setVerifyButtonEnabled(true);

            mLoginActivityFragment.setStatusTextText("Try again");
            mLoginActivityFragment.setStatusTextText("An error occurred when generating your keys and certificates.");
        }
    };

    private void setUpRviAndConnectToServer(KeyStore serverCertificateKeyStore, KeyStore deviceCertificateKeyStore, String deviceCertificatePassword, ArrayList<String> newCredentials) {
        try {
            RVILocalNode.setServerKeyStore(serverCertificateKeyStore);
            RVILocalNode.setDeviceKeyStore(deviceCertificateKeyStore);
            RVILocalNode.setDeviceKeyStorePassword(deviceCertificatePassword);

            if (newCredentials != null)
                RVILocalNode.setCredentials(this, newCredentials);

            ServerNode.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void launchLockActivityWhenReady() {
        if (mBluetoothRangingServiceConnected && mAllValidCertsAcquired) {
            Intent intent = new Intent();

            intent.setClass(LoginActivity.this, LockActivity.class);
            startActivity(intent);
        }
    }

    private ServiceConnection mConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {

            mBluetoothRangingServiceConnected = true;

            mBluetoothRangingService = ((BluetoothRangingService.BluetoothRangingServiceBinder)service).getService();

            mBluetoothRangingService
                    .servicesAvailable()
                    .subscribeOn(Schedulers.newThread())
                    .observeOn(AndroidSchedulers.mainThread())
                    .subscribe(new Observer<String>() {
                        @Override
                        public void onCompleted() {

                        }

                        @Override
                        public void onError(Throwable e) {

                        }

                        @Override
                        public void onNext(String s) {
                            Log.i(TAG, "X: " + s);
                            mLoginActivityFragment.onNewServiceDiscovered(s);
                        }
                    });

            Toast.makeText(LoginActivity.this, "Bluetooth ranger service connected", Toast.LENGTH_SHORT).show();

            launchLockActivityWhenReady();
        }

        public void onServiceDisconnected(ComponentName className) {
            mBluetoothRangingServiceConnected = false;

            mBluetoothRangingService = null;
            Toast.makeText(LoginActivity.this, "Bluetooth ranger service disconnected", Toast.LENGTH_SHORT).show();
        }
    };

    void doBindService() {
        bindService(new Intent(LoginActivity.this, BluetoothRangingService.class), mConnection, Context.BIND_AUTO_CREATE);
        mBluetoothRangingServiceBound = true;
    }

    void doUnbindService() {
        if (mBluetoothRangingServiceBound) {
            unbindService(mConnection);
            mBluetoothRangingServiceBound = false;
        }
    }

    @Override
    public void onButtonCommand(View v) {
        submit(v);
    }

    public void submit(View v) {

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        String email = prefs.getString("savedEmail", "");

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        mLoginActivityFragment.setVerifyButtonEnabled(false);
        mLoginActivityFragment.setStatusTextText("Connecting to server. Please check your email in a few minutes.");

        PKIManager.generateKeyPairAndCertificateSigningRequest(this, mCertificateSigningRequestGeneratorListener,
                start.getTime(), end.getTime(), X509_PRINCIPAL_PATTERN, RVILocalNode.getLocalNodeIdentifier(this), X509_ORG_UNIT, email.replace("+", "\\+"));
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_login, menu);
        return true;
    }

    void confirmationAlert(final int id, String actionMessage) {
        DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener()
        {
            public void onClick(DialogInterface dialog, int which) {
                switch (which) {
                    case DialogInterface.BUTTON_POSITIVE:
                        if (id == R.id.action_delete_all_keys_certs) {

                            ServerNode.disconnect();

                            PKIManager.deleteAllKeysAndCerts(LoginActivity.this);
                            RVILocalNode.removeAllCredentials(LoginActivity.this);
                            ServerNode.deleteUserData();

                            mValidatingToken       = false;
                            mAllValidCertsAcquired = false;

                            mLoginActivityFragment.setStatusTextText("The RVI Unlock Demo needs to verify your email address.");
                            mLoginActivityFragment.hideControls(false);
                            mLoginActivityFragment.setVerifyButtonEnabled(true);


                        } else if (id == R.id.action_delete_server_certs) {

                            ServerNode.disconnect();

                            PKIManager.deleteServerCerts(LoginActivity.this);
                            RVILocalNode.removeAllCredentials(LoginActivity.this);

                            mValidatingToken       = false;
                            mAllValidCertsAcquired = false;

                            mLoginActivityFragment.setStatusTextText("The RVI Unlock Demo needs to verify your email address.");
                            mLoginActivityFragment.hideControls(false);
                            mLoginActivityFragment.setVerifyButtonEnabled(true);

                        } else if (id == R.id.action_restore_defaults) {

                            PreferenceManager.getDefaultSharedPreferences(LoginActivity.this).edit().clear().apply();
                            PreferenceManager.setDefaultValues(LoginActivity.this, R.xml.advanced, true);

                        }

                        break;

                    case DialogInterface.BUTTON_NEGATIVE:

                        break;
                }
            }
        };

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setMessage("Are you sure you want to " + actionMessage + "?")
                .setPositiveButton("Yes", dialogClickListener)
                .setNegativeButton("Cancel", dialogClickListener).show();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent intent = new Intent();

            intent.setClass(LoginActivity.this, AdvancedPreferenceActivity.class);
            startActivityForResult(intent, 0);

            return true;

        } else if (id == R.id.action_delete_all_keys_certs) {
            confirmationAlert(id, "delete all your keys and certificates");

        } else if (id == R.id.action_delete_server_certs) {
            confirmationAlert(id, "delete the server certificates");

        } else if (id == R.id.action_restore_defaults) {
            confirmationAlert(id, "reset all the settings");

        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy() Activity");
        doUnbindService();

        super.onDestroy();
    }

    private void handleExtra(Intent intent) {
        Bundle extras = intent.getExtras();

        if (extras != null && extras.size() > 0 ) {
            for(String k : extras.keySet()) {
                Log.i(TAG, "k = " + k + " : " + extras.getString(k));
            }
        }

        if (extras != null && "dialog".equals(extras.get("_extra1"))) {
            AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(this);

            alertDialogBuilder.setTitle("" + extras.get("_extra2"));
            alertDialogBuilder
                    .setMessage("" + extras.get("_extra3"))
                    .setCancelable(false)
                    .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            dialog.cancel();
                        }
                    });

            alertDialogBuilder.create().show();
        }
    }
}
