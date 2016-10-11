package com.jaguarlandrover.auto.remote.vehicleentry;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * Copyright (c) 2015 Jaguar Land Rover.
 *
 * This program is licensed under the terms and conditions of the
 * Mozilla Public License, version 2.0. The full text of the
 * Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
 *
 * File:    RVIManager.java
 * Project: UnlockDemo
 *
 * Created by Lilli Szafranski on 10/28/15.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.util.Log;
import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;
import com.jaguarlandrover.pki.PKIManager;
import com.jaguarlandrover.rvi.RVILocalNode;
import com.jaguarlandrover.rvi.RVIRemoteNode;
import com.jaguarlandrover.rvi.RVIRemoteNodeListener;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

class ServerNode
{
    private final static String TAG = "UnlockDemo:ServerNode";

    /* * * * * * * * * * * * * * * * * * * * Static variables * * * * * * * * * * * * * * * * * * **/
    private static Context applicationContext = UnlockApplication.getContext();

    private static SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(applicationContext);
    private static Gson              gson        = new Gson();

    private static RVIRemoteNode rviNode = new RVIRemoteNode(null);

    private static final ConcurrentHashMap<String, String> certs = new ConcurrentHashMap<String, String>(1);

    /* * * * * * * * * * * * * * * * * * SharedPreferences keys * * * * * * * * * * * * * * * * * **/
    //private final static String NEW_CERTIFICATE_DATA_KEY        = "NEW_CERTIFICATE_DATA_KEY";
    //private final static String CERTIFICATE_DATA_KEY            = "CERTIFICATE_DATA_KEY";
    private final static String NEW_USER_DATA_KEY               = "NEW_USER_DATA_KEY";
    private final static String USER_DATA_KEY                   = "USER_DATA_KEY";
    //private final static String NEW_REMOTE_CREDENTIALS_LIST_KEY = "NEW_REMOTE_CREDENTIALS_LIST_KEY";
    //private final static String REMOTE_CREDENTIALS_LIST_KEY     = "REMOTE_CREDENTIALS_LIST_KEY";
    private final static String NEW_INVOKED_SERVICE_REPORT_KEY  = "NEW_INVOKED_SERVICE_REPORT_KEY";
    private final static String INVOKED_SERVICE_REPORT_KEY      = "INVOKED_SERVICE_REPORT_KEY";


    /* * * * * * * * * * * * * * * * * RVI service identifier parts * * * * * * * * * * * * * * * **/
    /* * * *  Service bundle * * * */
    private final static String CREDENTIAL_MANAGEMENT_BUNDLE = "credential_management";
    /* Local services */
    private final static String REVOKE_CREDENTIALS  = "revoke_credentials";
    private final static String UPDATE_CREDENTIALS  = "update_credentials";
    /* Remote services */
    private final static String REQUEST_CREDENTIALS = "request_credentials";

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    /* * * *  Service bundle * * * */
    private final static String ACCOUNT_MANAGEMENT_BUNDLE = "account_management";
    /* Remote services */
    private final static String AUTHORIZE_SERVICES   = "authorize_services";
    private final static String REVOKE_AUTHORIZATION = "revoke_authorization";
    /* Local and remote services */
    private final static String GET_USER_DATA = "get_user_data";
    private final static String SET_USER_DATA = "set_user_data";

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    /* * * *  Service bundle * * * */
    private final static String REPORTING_BUNDLE = "report";
    /* Remote services */
    private final static String SERVICE_INVOKED_BY_GUEST  = "service_invoked_by_guest";


    /* * * * * * * * * * * * * * * * Local service identifier lists * * * * * * * * * * * * * * * **/
    private final static ArrayList<String> credentialManagementBundleLocalServiceIdentifiers =
            new ArrayList<>(Arrays.asList(
                    CREDENTIAL_MANAGEMENT_BUNDLE + "/" + REVOKE_CREDENTIALS,
                    CREDENTIAL_MANAGEMENT_BUNDLE + "/" + UPDATE_CREDENTIALS));

    @SuppressWarnings("ArraysAsListWithZeroOrOneArgument")
    private final static ArrayList<String> accountManagementBundleLocalServiceIdentifiers =
            new ArrayList<>(Arrays.asList(
                    ACCOUNT_MANAGEMENT_BUNDLE + "/" + SET_USER_DATA));

    @SuppressWarnings("ArraysAsListWithZeroOrOneArgument")
    private final static ArrayList<String> reportingBundleLocalServiceIdentifiers =
            new ArrayList<>(Arrays.asList(
                    REPORTING_BUNDLE + "/" + SERVICE_INVOKED_BY_GUEST));


    private enum ConnectionStatus
    {
        DISCONNECTED,
        CONNECTING,
        CONNECTED
    }

    private static ConnectionStatus connectionStatus = ConnectionStatus.DISCONNECTED;
    private static boolean needsToRequestNewCredentials = false;

    private static ServerNode ourInstance = new ServerNode();

    private ServerNode() {

        RVIRemoteNodeListener nodeListener = new RVIRemoteNodeListener()
        {
            @Override
            public void nodeDidConnect(RVIRemoteNode node) {
                Log.d(TAG, "Connected to RVI provisioning server!");
                connectionStatus = ConnectionStatus.CONNECTED;

                needsToRequestNewCredentials = true;

                stopRepeatingTask();
            }

            @Override
            public void nodeDidFailToConnect(RVIRemoteNode node, Throwable reason) {
                Log.d(TAG, "Failed to connect to RVI provisioning server!");
                connectionStatus = ConnectionStatus.DISCONNECTED;

                //startRepeatingTask();
            }

            @Override
            public void nodeDidDisconnect(RVIRemoteNode node, Throwable reason) {
                Log.d(TAG, "Disconnected from RVI provisioning server!");
                connectionStatus = ConnectionStatus.DISCONNECTED;

                /* Try and reconnect */
                startRepeatingTask();
            }

            @Override
            public void nodeSendServiceInvocationSucceeded(RVIRemoteNode node, String serviceIdentifier) {

            }

            @Override
            public void nodeSendServiceInvocationFailed(RVIRemoteNode node, String serviceIdentifier, Throwable reason) {

            }

            @Override
            public void nodeReceiveServiceInvocationSucceeded(RVIRemoteNode node, String serviceIdentifier, Object parameters) {
                String[] serviceParts = serviceIdentifier.split("/");

                if (serviceParts.length < 2) return;

                switch (serviceParts[0]) {
                    case CREDENTIAL_MANAGEMENT_BUNDLE:
                        switch (serviceParts[1]) {
                            case UPDATE_CREDENTIALS:

                                // TODO: Check this
                                ArrayList<String> credentials = (ArrayList<String>) ((LinkedTreeMap<String, Object>) parameters).get("credentials");
                                RVILocalNode.setCredentials(applicationContext, credentials);

                                break;

                            case REVOKE_CREDENTIALS:

                                RVILocalNode.setCredentials(applicationContext, null);

                                break;

                        }

                        break;

                    case ACCOUNT_MANAGEMENT_BUNDLE:
                        switch (serviceParts[1]) {
                            case SET_USER_DATA:

                                ServerNode.setUserData(gson.toJson(parameters));

                                break;
                        }

                        break;

                    case REPORTING_BUNDLE:
                        switch (serviceParts[1]) {
                            case SERVICE_INVOKED_BY_GUEST:

                                ServerNode.setInvokedServiceReport(gson.toJson(parameters));

                                break;
                        }

                        break;

                }
            }

            @Override
            public void nodeReceiveServiceInvocationFailed(RVIRemoteNode node, String serviceIdentifier, Throwable reason) {

            }

            @Override
            public void nodeDidAuthorizeLocalServices(RVIRemoteNode node, Set<String> serviceIdentifiers) {
                Log.d(TAG, "Local services available: " + serviceIdentifiers.toString());
            }

            @Override
            public void nodeDidAuthorizeRemoteServices(RVIRemoteNode node, Set<String> serviceIdentifiers) {
                Log.d(TAG, "Remote services available: " + serviceIdentifiers.toString());

                for (String serviceIdentifier : serviceIdentifiers) {
                    if (serviceIdentifier.equals(CREDENTIAL_MANAGEMENT_BUNDLE + "/" + REQUEST_CREDENTIALS)) {
                        if (needsToRequestNewCredentials) {
                            needsToRequestNewCredentials = false;
                            requestCredentials();
                        }
                    } else if (serviceIdentifier.equals(ACCOUNT_MANAGEMENT_BUNDLE + "/" + GET_USER_DATA)) {
                        requestUserData();
                    }
                }
            }
        };

        rviNode.setListener(nodeListener);

        RVILocalNode.addLocalServices(UnlockApplication.getContext(), credentialManagementBundleLocalServiceIdentifiers);
        RVILocalNode.addLocalServices(UnlockApplication.getContext(), accountManagementBundleLocalServiceIdentifiers);
        RVILocalNode.addLocalServices(UnlockApplication.getContext(), reportingBundleLocalServiceIdentifiers);
    }

    Handler  timerHandler  = new Handler();
    Runnable timerRunnable = new Runnable()
    {
        @Override
        public void run() {
            if (connectionStatus == ConnectionStatus.DISCONNECTED) connect();

            timerHandler.postDelayed(this, 3000);
        }
    };

    private void startRepeatingTask() {
        timerHandler.postDelayed(timerRunnable, 30 * 1000);
    }

    private void stopRepeatingTask() {
        timerHandler.removeCallbacks(timerRunnable);
    }

    static void connect() {
        Log.d(TAG, "Attempting to connect to RVI provisioning server.");

        rviNode.setServerUrl(preferences.getString("pref_rvi_server", "38.129.64.40"));
        rviNode.setServerPort(Integer.parseInt(preferences.getString("pref_rvi_server_port", "8807")));

        connectionStatus = ConnectionStatus.CONNECTING;

        rviNode.connect();
    }

    static void requestCredentials() {
        Log.d(TAG, "Requesting credentials from RVI provisioning server.");

        if (connectionStatus == ConnectionStatus.DISCONNECTED) connect();

        HashMap<String, String> parameters = new HashMap<>();

        try {
            parameters.put("node_identifier", RVILocalNode.getLocalNodeIdentifier(applicationContext).substring("android/".length()));
            parameters.put("public_key", PKIManager.getPublicKey(applicationContext));
        } catch (Exception e) {
            e.printStackTrace();
        }

        rviNode.invokeService(CREDENTIAL_MANAGEMENT_BUNDLE + "/" + REQUEST_CREDENTIALS, parameters, 60 * 1000);
    }

    static void requestUserData() {
        Log.d(TAG, "Requesting user data from RVI provisioning server.");

        if (connectionStatus == ConnectionStatus.DISCONNECTED) connect();

        HashMap<String, String> parameters = new HashMap<>();

        try {
            parameters.put("node_identifier", RVILocalNode.getLocalNodeIdentifier(applicationContext).substring("android/".length()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        rviNode.invokeService(ACCOUNT_MANAGEMENT_BUNDLE + "/" + GET_USER_DATA, parameters, 60 * 1000);
    }

    static void revokeAuthorization(User remoteUser) {//UserCredentials remoteCredentials) {
        Log.d(TAG, "Revoking authorization for user on RVI provisioning server.");

        if (connectionStatus == ConnectionStatus.DISCONNECTED) connect();

        rviNode.invokeService(ACCOUNT_MANAGEMENT_BUNDLE + "/" + REVOKE_AUTHORIZATION, remoteUser, 60 * 1000);
        //rviNode.invokeService(CREDENTIAL_MANAGEMENT_BUNDLE + "/" + CERT_MODIFY, remoteCredentials, 5000);
    }

    static void authorizeServices(User remoteUser) {//UserCredentials remoteCredentials) {
        Log.d(TAG, "Creating remote credentials on RVI provisioning server.");

        if (connectionStatus == ConnectionStatus.DISCONNECTED) connect();

        rviNode.invokeService(ACCOUNT_MANAGEMENT_BUNDLE + "/" + AUTHORIZE_SERVICES, remoteUser, 60 * 1000);
        //rviNode.invokeService(CREDENTIAL_MANAGEMENT_BUNDLE + "/" + CERT_CREATE, remoteCredentials, 5000);
    }

//    public static Certificate getCertificate() {
//        String certStr = preferences.getString(CERTIFICATE_DATA_KEY, null);
//
//        Certificate certificate = new Certificate();
//        try {
//            certificate =  gson.fromJson(certStr, Certificate.class);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        return certificate;
//    }
//
//    private static void setCertificate(String certStr) {
//        SharedPreferences.Editor editor = preferences.edit();
//        editor.putString(CERTIFICATE_DATA_KEY, certStr);
//        editor.commit();
//
//        ServerNode.setThereIsNewCertificateData(true);
//    }

    static User getUserData() {
        String userStr = preferences.getString(USER_DATA_KEY, null);

        User userData = new User();
        try {
            if (userStr != null)
                userData = gson.fromJson(userStr, User.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return userData;
    }

    private static void setUserData(String userCredsStr) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(USER_DATA_KEY, userCredsStr);
        editor.commit();

        ServerNode.setThereIsNewUserData(true);
    }

//    static Collection<UserCredentials> getRemoteCredentialsList() {
//        String credListStr = preferences.getString(REMOTE_CREDENTIALS_LIST_KEY, null);
//
//        if (credListStr == null) return null;
//
//        Collection<UserCredentials> credsList = null;
//        Type collectionType = new TypeToken<Collection<UserCredentials>>()
//        {
//        }.getType();
//
//        try {
//            credsList = gson.fromJson(credListStr, collectionType);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        return credsList;
//    }
//
//    private static void setRemoteCredentialsList(String credsListStr) {
//        SharedPreferences.Editor editor = preferences.edit();
//        editor.putString(REMOTE_CREDENTIALS_LIST_KEY, credsListStr);
//        editor.commit();
//
//        ServerNode.setThereAreNewRemoteCredentials(true);
//    }

    static InvokedServiceReport getInvokedServiceReport() {
        String reportStr = preferences.getString(INVOKED_SERVICE_REPORT_KEY, null);

        InvokedServiceReport report = null;
        try {
            report = gson.fromJson(reportStr, InvokedServiceReport.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return report;
    }

    private static void setInvokedServiceReport(String reportStr) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(INVOKED_SERVICE_REPORT_KEY, reportStr);
        editor.commit();

        ServerNode.setThereIsNewInvokedServiceReport(true);
    }

//    public static Boolean thereIsNewCertificateData() {
//        return preferences.getBoolean(NEW_CERTIFICATE_DATA_KEY, false);
//    }
//
//    private static void setThereIsNewCertificateData(Boolean isNewActivity) {
//        SharedPreferences.Editor editor = preferences.edit();
//        editor.putBoolean(NEW_CERTIFICATE_DATA_KEY, isNewActivity);
//        editor.commit();
//    }

    static Boolean thereIsNewUserData() {
        return preferences.getBoolean(NEW_USER_DATA_KEY, false);
    }

    static void setThereIsNewUserData(Boolean thereIsNewUserData) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putBoolean(NEW_USER_DATA_KEY, thereIsNewUserData);
        editor.commit();
    }

//    static Boolean thereAreNewRemoteCredentials() {
//        return preferences.getBoolean(NEW_REMOTE_CREDENTIALS_LIST_KEY, false);
//    }
//
//    static void setThereAreNewRemoteCredentials(Boolean areNewCredentials) {
//        SharedPreferences.Editor editor = preferences.edit();
//        editor.putBoolean(NEW_REMOTE_CREDENTIALS_LIST_KEY, areNewCredentials);
//        editor.commit();
//    }

    static Boolean thereIsNewInvokedServiceReport() {
        return preferences.getBoolean(NEW_INVOKED_SERVICE_REPORT_KEY, false);
    }

    static void setThereIsNewInvokedServiceReport(Boolean isNewReport) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putBoolean(NEW_INVOKED_SERVICE_REPORT_KEY, isNewReport);
        editor.commit();
    }

//    private static String[] parseAndValidateJWT(String encToken) {
//        String[] result = new String[3];
//
//        String [] jwtParts = encToken.split("\\.");
//        if (jwtParts[0] != null) result[0] = new String(Base64.decode(jwtParts[0], Base64.URL_SAFE));
//        if (jwtParts[1] != null) result[1] = new String(Base64.decode(jwtParts[1], Base64.URL_SAFE));
//        if (jwtParts[2] != null) result[2] = new String(Base64.decode(jwtParts[2], Base64.URL_SAFE));
//
//        return result;
//    }
}
