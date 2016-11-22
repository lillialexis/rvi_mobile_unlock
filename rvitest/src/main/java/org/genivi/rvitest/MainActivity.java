package org.genivi.rvitest;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.jaguarlandrover.pki.PKICertificateResponse;
import com.jaguarlandrover.pki.PKICertificateSigningRequestRequest;
import com.jaguarlandrover.pki.PKIManager;
import com.jaguarlandrover.pki.PKIServerResponse;
import com.jaguarlandrover.rvi.RVILocalNode;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Calendar;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "RVITest/MainActivity___";

    private final static String X509_PRINCIPAL_PATTERN = "CN=%s, O=Genivi, OU=%s";
    private final static String X509_ORG_UNIT          = "Android Unlock App";
    private final static String RVI_DOMAIN             = "genivi.org";

    private final static String PROVISIONING_SERVER_BASE_URL = "http://38.129.64.40:8000";
    private final static String PROVISIONING_SERVER_CSR_URL  = "/csr_veh";

    private Button testSetButton1;
    private Button testSetButton2;
    private Button testSetButton3;
    private Button testSetButton4;
    private Button testSetButton5;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        testSetButton1 = (Button) this.findViewById(R.id.test_set_button_1);
        testSetButton2 = (Button) this.findViewById(R.id.test_set_button_2);
        testSetButton3 = (Button) this.findViewById(R.id.test_set_button_3);
        testSetButton4 = (Button) this.findViewById(R.id.test_set_button_4);
        testSetButton5 = (Button) this.findViewById(R.id.test_set_button_5);

        testSetButton1.setOnClickListener(buttonListener);
        testSetButton2.setOnClickListener(buttonListener);
        testSetButton3.setOnClickListener(buttonListener);
        testSetButton4.setOnClickListener(buttonListener);
        testSetButton5.setOnClickListener(buttonListener);

        RVILocalNode.start(this, RVI_DOMAIN);

        if (PKIManager.hasValidDeviceCert(this) && PKIManager.hasValidServerCert(this)) {
            setUpRviAndConnectToServer(PKIManager.getServerKeyStore(this), PKIManager.getDeviceKeyStore(this), null, null);
        } else {
            generateKeysAndCerts();
        }
    }

    private void generateKeysAndCerts() {
        Log.d(TAG, "Certs not found. Generating keys and certs...");

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        PKIManager.generateKeyPairAndCertificateSigningRequest(this, new PKIManager.CertificateSigningRequestGeneratorListener() {
            @Override
            public void generateCertificateSigningRequestSucceeded(String certificateSigningRequest) {
                Log.d(TAG, "Certificate signing request generated. Sending to server...");

                sendCertificateSigningRequest(certificateSigningRequest);
            }

            @Override
            public void generateCertificateSigningRequestFailed(Throwable reason) {
                Log.e(TAG, reason.getLocalizedMessage());
            }

        }, start.getTime(), end.getTime(), X509_PRINCIPAL_PATTERN, RVILocalNode.getLocalNodeIdentifier(this), X509_ORG_UNIT);
    }

    private void sendCertificateSigningRequest(String certificateSigningRequest) {
        PKICertificateSigningRequestRequest request = new PKICertificateSigningRequestRequest(certificateSigningRequest);

        PKIManager.sendCertificateSigningRequest(this, new PKIManager.ProvisioningServerListener() {
            @Override
            public void managerDidReceiveResponseFromServer(PKIServerResponse response) {
                if (response.getStatus() == PKIServerResponse.Status.VERIFICATION_NEEDED) {
                    Log.e(TAG, "Problem: verification needed...");

                } else if (response.getStatus() == PKIServerResponse.Status.CERTIFICATE_RESPONSE) {
                    Log.d(TAG, "Certificate signing request received and server sent back certs and creds.");

                    PKICertificateResponse certificateResponse = (PKICertificateResponse) response;

                    setUpRviAndConnectToServer(certificateResponse.getServerKeyStore(), certificateResponse.getDeviceKeyStore(), null, certificateResponse.getJwtCredentials());

                } else if (response.getStatus() == PKIServerResponse.Status.ERROR) {
                    Log.e(TAG, "Error from server");

                }
            }

        }, PROVISIONING_SERVER_BASE_URL, PROVISIONING_SERVER_CSR_URL, request);

    }

    private void setUpRviAndConnectToServer(KeyStore serverCertificateKeyStore, KeyStore deviceCertificateKeyStore, String deviceCertificatePassword, ArrayList<String> newCredentials) {
        try {
            RVILocalNode.setServerKeyStore(serverCertificateKeyStore);
            RVILocalNode.setDeviceKeyStore(deviceCertificateKeyStore);
            RVILocalNode.setDeviceKeyStorePassword(deviceCertificatePassword);

            TestServerNode.connect();

            testSetButton1.setEnabled(true);
            testSetButton2.setEnabled(true);
            testSetButton3.setEnabled(true);
            testSetButton4.setEnabled(true);
            testSetButton5.setEnabled(true);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    Button.OnClickListener buttonListener = new View.OnClickListener() {

        @Override
        public void onClick(View view) {
            Intent intent = new Intent();

            if (view == testSetButton1)
                intent.setClass(MainActivity.this, TestSet1Activity.class);
            else if (view == testSetButton2)
                intent.setClass(MainActivity.this, TestSet2Activity.class);
            else if (view == testSetButton3)
                intent.setClass(MainActivity.this, TestSet3Activity.class);
            else if (view == testSetButton4)
                intent.setClass(MainActivity.this, TestSet4Activity.class);
            else if (view == testSetButton5)
                intent.setClass(MainActivity.this, TestSet5Activity.class);

            startActivityForResult(intent, 0);
        }
    };
}
