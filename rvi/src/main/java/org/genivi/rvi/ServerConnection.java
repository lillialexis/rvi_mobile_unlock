package org.genivi.rvi;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * Copyright (c) 2015 Jaguar Land Rover.
 *
 * This program is licensed under the terms and conditions of the
 * Mozilla Public License, version 2.0. The full text of the
 * Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
 *
 * File:    ServerConnection.java
 * Project: RVI
 *
 * Created by Lilli Szafranski on 5/19/15.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

import android.os.AsyncTask;
import android.util.Log;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * The TCP/IP server @RemoteConnectionInterface implementation
 */
class ServerConnection implements RemoteConnectionInterface
{
    private final static String TAG = "RVI/ServerConnection___";
    private RemoteConnectionListener mRemoteConnectionListener;

    private String  mServerUrl;
    private Integer mServerPort;

    private java.security.cert.Certificate mRemoteDeviceCertificate;

    private KeyStore mServerKeyStore = null;
    private KeyStore mLocalDeviceKeyStore = null;
    private String   mLocalDeviceKeyStorePassword = null;

    private SSLSocket mSocket;

    @Override
    public void sendRviRequest(DlinkPacket dlinkPacket) {
        if (!isConfigured())
            mRemoteConnectionListener.onDidFailToSendDataToRemoteConnection(new Throwable("RVI node is not configured."));
        else if (!isConnected())
            mRemoteConnectionListener.onDidFailToSendDataToRemoteConnection(new Throwable("RVI node is not connected."));
        else
            new SendDataTask(dlinkPacket).executeOnExecutor(AsyncTask.SERIAL_EXECUTOR);
    }

    @Override
    public boolean isConnected() {
        return mSocket != null && mSocket.isConnected();
    }

    @Override
    public boolean isConfigured() {
        return !(mServerUrl == null || mServerUrl.isEmpty() || mServerPort == 0 || mServerKeyStore == null || mLocalDeviceKeyStore == null);
    }

    @Override
    public void connect() {
        if (isConnected()) disconnect(null);

        connectSocket();
    }

    @Override
    public void disconnect(Throwable trigger) {

        try {
            if (mSocket != null)
                mSocket.close();

        } catch (Exception e) {
            if (e.getLocalizedMessage() != null)
                Log.d(TAG, e.getLocalizedMessage());
        }

        mRemoteDeviceCertificate = null;
        mSocket                  = null;

        if (mRemoteConnectionListener != null) mRemoteConnectionListener.onRemoteConnectionDidDisconnect(trigger);
    }

    @Override
    public void setRemoteConnectionListener(RemoteConnectionListener remoteConnectionListener) {
        mRemoteConnectionListener = remoteConnectionListener;
    }

    private void connectSocket() {
        Log.d(TAG, "Connecting the socket: " + mServerUrl + ":" + mServerPort);

        ConnectTask connectAndAuthorizeTask = new ConnectTask(mServerUrl, mServerPort, mServerKeyStore, mLocalDeviceKeyStore, mLocalDeviceKeyStorePassword);
        connectAndAuthorizeTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }

    private class ConnectTask extends AsyncTask<Void, String, Throwable>
    {
        String   dstAddress;
        int      dstPort;
        KeyStore serverKeyStore;
        KeyStore clientKeyStore;
        String   clientKeyStorePassword;

        ConnectTask(String addr, int port, KeyStore sks, KeyStore cks, String cksPass) {
            dstAddress = addr;
            dstPort = port;
            clientKeyStore = cks;
            serverKeyStore = sks;
            clientKeyStorePassword = cksPass;
        }

        @Override
        protected Throwable doInBackground(Void... params) {

            try {

                try {
                    KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
                    keyStore.load(null, null);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                Log.d(TAG, "Creating socket factory");

                String trustManagerAlgorithm = "X509";
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerAlgorithm);
                trustManagerFactory.init(serverKeyStore);

                String keyManagerAlgorithm = "X509";
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerAlgorithm);
                keyManagerFactory.init(clientKeyStore, clientKeyStorePassword != null ? clientKeyStorePassword.toCharArray() : null);

                SSLContext context = SSLContext.getInstance("TLS");
                context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

                SocketFactory sf = context.getSocketFactory();

                Log.d(TAG, "Creating ssl socket");

                mSocket = (SSLSocket) sf.createSocket(dstAddress, dstPort);

                SSLSession session  = mSocket.getSession();

                java.security.cert.Certificate[] peerCertificates = session.getPeerCertificates();

                if (peerCertificates == null || peerCertificates.length == 0 || peerCertificates.length > 2) {
                    throw new Exception("Remote certificate chain is null, empty, or contains more than 2 certificates.");
                }

                mRemoteDeviceCertificate = peerCertificates[0];

                /* If there is 1 certificate, then probably the remote device certificate is the same as the server certificate (e.g., I'm connected to the server).
                   If there are 2 certificates, then probably the first certificate is the device certificate and the second certificate is the servers. This
                   should match my server certificate, right? I'm assuming this array is ordered as such, but the documentation doesn't say. */

                Log.d(TAG, "Creating ssl socket complete");

            } catch (Exception e) {
                e.printStackTrace();

                return e;
            }

            return null;
        }

        @Override
        protected void onPostExecute(Throwable result) {
            super.onPostExecute(result);

            if (result == null) {
                // TODO: Does the input buffer stream cache data in the case that my async thread sends the auth command before the listener is set up?
                ListenTask listenTask = new ListenTask();
                listenTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);

                if (mRemoteConnectionListener != null)
                    mRemoteConnectionListener.onRemoteConnectionDidConnect();
            } else {
                if (mRemoteConnectionListener != null)
                    mRemoteConnectionListener.onRemoteConnectionDidFailToConnect(result);

                mSocket = null;
            }
        }
    }

    private class ListenTask extends AsyncTask<Void, String, Throwable>
    {
        @Override
        protected Throwable doInBackground(Void... params) {
            Log.d(TAG, "Listening on socket...");

            try {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(1024);
                byte[] buffer = new byte[1024];

                int bytesRead;
                InputStream inputStream = mSocket.getInputStream();

                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    byteArrayOutputStream.write(buffer, 0, bytesRead);

                    publishProgress(byteArrayOutputStream.toString("UTF-8"));
                    byteArrayOutputStream.reset();
                }
            } catch (Exception e) {
                e.printStackTrace();

                return e;
            }

            return null;
        }

        @Override
        protected void onProgressUpdate(String... params) {
            super.onProgressUpdate(params);

            String data = params[0];

            if (mRemoteConnectionListener != null) mRemoteConnectionListener.onRemoteConnectionDidReceiveData(data);
        }

        @Override
        protected void onPostExecute(Throwable result) {
            super.onPostExecute(result);

            disconnect(result);
        }
    }

    private class SendDataTask extends AsyncTask<Void, Void, Throwable>
    {
        private DlinkPacket mPacket;
        SendDataTask(DlinkPacket packet) {
            mPacket = packet;
        }

        @Override
        protected Throwable doInBackground(Void... params) {

            String data = mPacket.toJsonString();

            try {
                DataOutputStream wr = new DataOutputStream(mSocket.getOutputStream());

                wr.writeBytes(data);
                wr.flush();
            } catch (Exception e) {
                e.printStackTrace();

                return e;
            }

            return null;
        }

        @Override
        protected void onPostExecute(Throwable result) {
            if (result == null) {
                if (mRemoteConnectionListener != null) mRemoteConnectionListener.onDidSendDataToRemoteConnection(mPacket);
            } else {
                if (mRemoteConnectionListener != null) mRemoteConnectionListener.onDidFailToSendDataToRemoteConnection(result);

                disconnect(result);
            }
        }
    }

    void setServerUrl(String serverUrl) {
        mServerUrl = serverUrl;
    }

    void setServerPort(Integer serverPort) {
        mServerPort = serverPort;
    }

    public void setServerKeyStore(KeyStore serverKeyStore) {
        mServerKeyStore = serverKeyStore;
    }

    public void setLocalDeviceKeyStore(KeyStore localDeviceKeyStore) {
        mLocalDeviceKeyStore = localDeviceKeyStore;
    }

    public void setLocalDeviceKeyStorePassword(String localDeviceKeyStorePassword) {
        mLocalDeviceKeyStorePassword = localDeviceKeyStorePassword;
    }

    public Certificate getRemoteDeviceCertificate() {
        return mRemoteDeviceCertificate;
    }

    public Certificate getLocalDeviceCertificate() {
        try {
            if (mLocalDeviceKeyStore == null) throw new Exception("Device keystore is null");

            Enumeration<String> aliases = mLocalDeviceKeyStore.aliases();

            String alias = aliases.nextElement();

            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) mLocalDeviceKeyStore.getEntry(alias, null);

            return entry.getCertificate();
        } catch (Exception e) {
            e.printStackTrace();

            disconnect(e);
        }

        return null;
    }

    public Certificate getServerCertificate() {
        try {
            if (mServerKeyStore == null) throw new Exception("Server keystore is null");

            Enumeration<String> aliases = mServerKeyStore.aliases();

            String alias = aliases.nextElement();

            KeyStore.TrustedCertificateEntry entry = (KeyStore.TrustedCertificateEntry) mServerKeyStore.getEntry(alias, null);

            // TODO: Maybe check here if have more than one entry?

            return entry.getTrustedCertificate();
        } catch (Exception e) {
            e.printStackTrace();

            disconnect(e);
        }

        return null;
    }
}
