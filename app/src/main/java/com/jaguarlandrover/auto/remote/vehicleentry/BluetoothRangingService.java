/**
 *  Copyright (C) 2015, Jaguar Land Rover
 *
 *  This program is licensed under the terms and conditions of the
 *  Mozilla Public License, version 2.0.  The full text of the
 *  Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
 *
 */

package com.jaguarlandrover.auto.remote.vehicleentry;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import org.json.JSONObject;

import rx.Observable;
import rx.Subscriber;
import rx.schedulers.Schedulers;
import rx.subjects.PublishSubject;

public class BluetoothRangingService extends Service {
    private static final String TAG = "UnlockDemo/RviService__";

    private SharedPreferences prefs;

    public BluetoothRangingService() {
    }

    /**
     * Class for clients to access.  Because we know this service always
     * runs in the same process as its clients, we don't need to deal with
     * IPC.
     */
    public class BluetoothRangingServiceBinder extends Binder
    {
        BluetoothRangingService getService() {
            return BluetoothRangingService.this;
        }
    }

    private BeaconRanger br = null;

    @Override
    public void onCreate() {
        Log.d(TAG, "onCreate Service");

        super.onCreate();

        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        //TODO base on VIN instead

        br = new BeaconRanger(this);
        //br.addVinMask("3C3CFFGE8ET291409"); //My Fiat
        //br.addVinMask("3C3CFFGE8ET"); //Lots of fiats
        //br.addVinMask("3"); //Lots of cars
        br.start();
        Observable<RangeObject> obs =  br.getRangeStream();
        obs.observeOn(Schedulers.newThread()).subscribeOn(Schedulers.newThread()).subscribe(beaconSubscriber);
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy() Service");

        br.stop();
    }

    private PublishSubject<String> commandSink = PublishSubject.create();

    public Observable<String> servicesAvailable() {
        return commandSink;
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "onBind");

        return mBinder;
    }

    // This is the object that receives interactions from clients.  See
    // RemoteService for a more complete example.
    private final IBinder mBinder = new BluetoothRangingServiceBinder();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand");

        starting(intent);
        return START_STICKY;
    }

    protected void starting(Intent intent) {
        if (intent != null && intent.getExtras() != null) {
            int btState = intent.getExtras().getInt("bluetooth", BluetoothAdapter.STATE_OFF);
            if (btState == BluetoothAdapter.STATE_ON) {
                Log.w(TAG, "BT on, start ranging");
                br.start();
            } else if (btState == BluetoothAdapter.STATE_OFF) {
                Log.w(TAG, "BT off, stop ranging");
                br.stop();
            }
        }
    }

    private static final PublishSubject<JSONObject> btSender = PublishSubject.create();

    private Subscriber<RangeObject> beaconSubscriber = new Subscriber<RangeObject>()
    {
        @Override
        public void onCompleted() {
            Log.i(TAG, "Beacon Ranger DONE");
        }

        @Override
        public void onError(Throwable e) {
            Log.e(TAG, "", e);
        }

        @Override
        public void onNext(final RangeObject ro) {
            final boolean connected  = VehicleNode.isConnected();
            final boolean connecting = VehicleNode.isConnecting();
            final boolean unlocked   = VehicleNode.isUnlocked();

            final double unlockDistance  = Double.parseDouble(prefs.getString("pref_auto_unlock_dist", "1"));
            final double connectDistance = Double.parseDouble(prefs.getString("pref_auto_conn_dist", "3"));

            double grayArea = Double.parseDouble(prefs.getString("pref_auto_lock_unlock_cutoff_gray_area", "0.4"));
            if (grayArea > 1.0 || grayArea < 0.0) {
                Log.d(TAG, "Invalid grayArea: " + grayArea + "! Resetting to default value of 0.4");
                grayArea = 0.4;
            }

            final double weightedCutoff = ((1.0 - grayArea) / 2.0);

            Log.d(TAG, "distance:" + ro.distance + ", weightedDistance:" + ro.weightedDistance + ", unlockDistance:" + unlockDistance + ", connectDistance:" + connectDistance);
            Log.d(TAG, "connected:" + connected + ", connecting:" + connecting + ", unlocked:" + unlocked);

            User user = null;
            Vehicle vehicle = null;

            try {
                user = ServerNode.getUserData();

                if (user.getSelectedVehicleIndex() == -1)
                    return;

                vehicle = user.getVehicles().get(user.getSelectedVehicleIndex());

            } catch (Exception justHereBecauseOfWeirdExceptionThatHappensOnLaunch) {
                justHereBecauseOfWeirdExceptionThatHappensOnLaunch.printStackTrace();

                return;
            }

            if (user != null) {
                try {
                    if (vehicle.getUserType().equals("guest") && (!vehicle.getAuthorizedServices().isLock() || !vehicle.isKeyValid())) { // TODO: Test
                        Log.d(TAG, "User is not authorized to lock/unlock car.");

                        return;
                    } else {
                        if (!connected && (ro.distance > connectDistance)) {
                            Log.d(TAG, "Too far out to connect : " + ro.distance);
                            return;
                        }

                        if (connected && (!unlocked) && (ro.weightedDistance > weightedCutoff)) {
                            Log.d(TAG, "Too far out unlock : " + ro.distance);
                            return;
                        }

                        if (connected && (!unlocked) && ro.weightedDistance <= weightedCutoff) {
                            VehicleNode.sendFobSignal(VehicleNode.FOB_SIGNAL_UNLOCK);
                            sendNotification(BluetoothRangingService.this, getResources().getString(R.string.not_auto_unlock));
                            return;
                        }

                        if (connected && unlocked && ro.weightedDistance >= (1.0 - weightedCutoff)) {
                            VehicleNode.sendFobSignal(VehicleNode.FOB_SIGNAL_LOCK);
                            sendNotification(BluetoothRangingService.this, getResources().getString(R.string.not_auto_lock));
                            return;
                        }

                        if (connecting) {
                            Log.d(TAG, "Already connecting to BT endpoint.");
                            return;
                        }

                        if (connected) {
                            Log.d(TAG, "Already connected to BT endpoint.");
                            return;
                        }

                    }
                } catch (Exception e) {
                    e.printStackTrace();

                    return;
                }
            }
        }
    };

    static void sendNotification(Context ctx, String action, String... extras) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        boolean fire = prefs.getBoolean("pref_fire_notifications", true);

        if (!fire) return;

        NotificationCompat.Builder builder =
                new NotificationCompat.Builder(ctx)
                        .setSmallIcon(R.drawable.rvi_not)
                        .setAutoCancel(true)
                        .setContentTitle(ctx.getResources().getString(R.string.app_name))
                        .setContentText(action);

        Intent targetIntent = new Intent(ctx, LockActivity.class);
        int j = 0;
        for (String ex : extras) {
            targetIntent.putExtra("_extra" + (++j), ex);
            targetIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        }
        PendingIntent contentIntent = PendingIntent.getActivity(ctx, 0, targetIntent, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setContentIntent(contentIntent);
        nm.notify(0, builder.build());
    }
}
