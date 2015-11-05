/**
 *  Copyright (C) 2015, Jaguar Land Rover
 *
 *  This program is licensed under the terms and conditions of the
 *  Mozilla Public License, version 2.0.  The full text of the
 *  Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
 *
 */

package com.jaguarlandrover.auto.remote.vehicleentry;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


public class LockActivity extends ActionBarActivity implements LockActivityFragment.LockFragmentButtonListener {
    private static final String TAG = "RVI";
    private boolean bound = false;
    private String username;
    private TextView userHeader;
    private Handler keyCheck;
    private Handler request;
    private Handler guestServiceCheck;
    LockActivityFragment lock_fragment = null;
    ProgressDialog requestProgress;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "onCreate() Activity");

//        sharedPref = PreferenceManager.getDefaultSharedPreferences(this);

        handleExtra(getIntent());

        keyCheck = new Handler();
        request = new Handler();
        guestServiceCheck = new Handler();

        setContentView(R.layout.activity_lock);
        lock_fragment = (LockActivityFragment) getFragmentManager().findFragmentById(R.id.fragmentlock);
        startRepeatingTask();
        //doBindService();
    }

    Runnable StatusCheck = new Runnable()
    {
        @Override
        public void run() {
            try {
                checkForKeys();
            } catch (Exception e1) {
                Log.w(TAG, "EXCEPTION Check for Key Status: " + e1.toString());
            }

            keyCheck.postDelayed(StatusCheck, 5000);
        }
    };

    Runnable guestCheck = new Runnable()
    {
        @Override
        public void run() {
            try {
                checkForGuestActivity();
            } catch (Exception e1) {
                Log.w(TAG, "JCheck for Guest Activity: " + e1.toString());
            }

            guestServiceCheck.postDelayed(guestCheck, 10000);
        }
    };

    Runnable requestCheck = new Runnable()
    {
        @Override
        public void run() {
            requestComplete();
            request.postDelayed(requestCheck, 750);
        }
    };

    void startRequest() {
        requestCheck.run();
    }

    void done() {
        request.removeCallbacks(requestCheck);
    }

    void startRepeatingTask() {
        StatusCheck.run();
        guestCheck.run();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleExtra(intent);
    }

    @Override
    public void onResume() {
        super.onResume();
    }

    private void handleExtra(Intent intent) {
        Bundle extras = intent.getExtras();
        if (extras != null && extras.size() > 0) {
            for (String k : extras.keySet()) {
                Log.i(TAG, "k = " + k + " : " + extras.getString(k));
            }
        }
        if (extras != null && "dialog".equals(extras.get("_extra1"))) {
            AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(this);
            alertDialogBuilder.setTitle("" + extras.get("_extra2"));
            alertDialogBuilder
                    .setMessage("" + extras.get("_extra3"))
                    .setCancelable(false)
                    .setPositiveButton("OK", new DialogInterface.OnClickListener()
                    {
                        public void onClick(DialogInterface dialog, int id) {
                            dialog.cancel();
                        }
                    });
            alertDialogBuilder.create().show();
        }
    }


    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy() Activity");
        //doUnbindService();

        super.onDestroy();
        //For testing cleanup
        //Intent i = new Intent(this, RviService.class);
        //stopService(i);
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_lock, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent intent = new Intent();
            intent.setClass(LockActivity.this, AdvancedPreferenceActivity.class);
            startActivityForResult(intent, 0);
            return true;
        } else if (id == R.id.action_reset) {
            PreferenceManager.getDefaultSharedPreferences(this).edit().clear().apply(); //reset
            PreferenceManager.setDefaultValues(this, R.xml.advanced, true);
            return true;
        } else if (id == R.id.action_quit) {
            Intent i = new Intent(this, RviService.class);
            stopService(i);
            finish();
        }

        return super.onOptionsItemSelected(item);
    }

//    public void clickedStart(View v){
//        SharedPreferences.Editor ed = sharedPref.edit();
//        ed.putBoolean(LockActivityFragment.STOPPED_LBL, true);
//        rviService.service("start", LockActivity.this);
//        ed.commit();
//    }

    @Override
    public void onButtonCommand(String cmd) {
        //TODO send to RVI service
        RviService.service(cmd, LockActivity.this);
    }

    public void keyUpdate(final AuthorizedServices authorizedServices, final String userType) {
        AlertDialog.Builder builder = new AlertDialog.Builder(LockActivity.this);
        builder.setInverseBackgroundForced(true);
        builder.setMessage("Key updates have been made").setCancelable(false).setPositiveButton("OK",
                new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        lock_fragment.setButtons(authorizedServices, userType);
                    }
                });
        AlertDialog alert = builder.create();
        alert.show();
    }

    public void notififyGuestUsedKey(final String guestUser, final String guestService) {
        AlertDialog.Builder builder = new AlertDialog.Builder(LockActivity.this);
        builder.setInverseBackgroundForced(true);
        builder.setMessage("Remote key used by "+ guestUser + "!")
                .setCancelable(true)
                .setPositiveButton("OK", new
                        DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.cancel();
                            }
                        });
        AlertDialog alert = builder.create();
        alert.show();
    }

    @Override
    public void keyShareCommand(String key) {
        Intent intent = new Intent();
        switch (key) {
            case "keyshare":
                intent.setClass(LockActivity.this, KeyShareActivity.class);
                startActivityForResult(intent, 0);
                break;
            case "keychange":
                try {
                    RviService.requestAll(Request(), LockActivity.this);
                    requestProgress = ProgressDialog.show(LockActivity.this, "","Retrieving keys...",true);

                    requestProgress.setCancelable(true);
                    requestProgress.setOnCancelListener(new DialogInterface.OnCancelListener()
                    {
                        @Override
                        public void onCancel(DialogInterface dialog) {
                             // TODO: ?
                        }
                    });

                    startRequest();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
        }
    }

    public JSONArray Request() throws JSONException, java.lang.NullPointerException {
        JSONObject request = new JSONObject();
        request.put("vehicleVIN", PrefsWrapper.getUserCredentials().getVehicleVin());

        JSONArray jsonArray = new JSONArray();
        jsonArray.put(request);
        return jsonArray;
    }

    public void checkForKeys() {
        UserCredentials userCredentials = PrefsWrapper.getUserCredentials();

        if (userCredentials != null && PrefsWrapper.thereAreNewUserCredentials()) {
            keyUpdate(userCredentials.getAuthorizedServices(), userCredentials.getUserType());
            PrefsWrapper.setThereAreNewUserCredentials(false);
        }
    }

    public void checkForGuestActivity() {
        InvokedServiceReport report = PrefsWrapper.getInvokedServiceReport();

        if (report != null && PrefsWrapper.thereIsNewInvokedServiceReport()) {
            notififyGuestUsedKey(report.getUserName(), report.getServiceIdentifier());
            PrefsWrapper.setThereIsNewInvokedServiceReport(false);
        }
    }

    public void requestComplete() {
        if (PrefsWrapper.thereAreNewRemoteCredentials()) {
            done();
            PrefsWrapper.setThereAreNewRemoteCredentials(false);
            requestProgress.dismiss();
            Intent intent = new Intent();
            intent.setClass(LockActivity.this, KeyRevokeActivity.class);
            startActivityForResult(intent, 0);
        }
    }
}
