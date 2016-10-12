package com.jaguarlandrover.auto.remote.vehicleentry;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.LinearLayout;
import android.widget.ListView;

import org.json.JSONArray;

import java.util.ArrayList;
import java.util.Arrays;


public class KeyRevokeActivity extends ActionBarActivity {
    LinearLayout layout;
    int mPosition;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_key_change);

        //ArrayList<UserCredentials> arrayofusers = new ArrayList<UserCredentials>();
        ArrayList<User> guestUsers = new ArrayList<User>();

        RemoteCredentialsAdapter adapter = new RemoteCredentialsAdapter(this, guestUsers);
        ListView listView = (ListView) findViewById(R.id.sharedKeys);
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener()
        {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                mPosition = position;
                alertMessage();
            }
        });

        listView.setAdapter(adapter);
        addUsers(adapter);
    }

    public void alertMessage(){
        DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener(){
            public void onClick(DialogInterface dialog, int which){
                switch(which){
                    case DialogInterface.BUTTON_POSITIVE:
                        try{
                            //RviService.revokeKey(selectKey());//share_fragment.getRemoteCredentials());
                            ServerNode.revokeAuthorization(selectKey());
                        } catch (Exception e){

                        }
                        finish();
                        break;
                    case DialogInterface.BUTTON_NEGATIVE:

                        break;
                }
            }
        };

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setMessage("Are you sure?")
                .setPositiveButton("Revoke Key", dialogClickListener)
                .setNegativeButton("Cancel", dialogClickListener).show();
    }

    //public UserCredentials selectKey() {
    public User selectKey() {
        JSONArray revokeKeyOuter = new JSONArray();
        JSONArray revokeKey = new JSONArray();

        //UserCredentials revokingCredentials = new UserCredentials();
        User revokingUser = new User();

        try {
            //ArrayList<UserCredentials> remoteCredentialsList = new ArrayList<>(ServerNode.getRemoteCredentialsList());
            ArrayList<User> guestUsers = ServerNode.getUserData().getGuests();//new ArrayList<>(ServerNode.getRemoteCredentialsList());

            //UserCredentials selectedRemoteCredentials = guestUsers.get(mPosition);
            User selectedGuest = guestUsers.get(mPosition);

//            /* Old code */
//            JSONObject payload = new JSONObject();
//            JSONArray authServices = new JSONArray();
//
//            authServices.put(new JSONObject().put("lock", "false"));
//            authServices.put(new JSONObject().put("start", "false"));
//            authServices.put(new JSONObject().put("trunk", "false"));
//            authServices.put(new JSONObject().put("windows", "false"));
//            authServices.put(new JSONObject().put("lights", "false"));
//            authServices.put(new JSONObject().put("hazard", "false"));
//            authServices.put(new JSONObject().put("horn", "false"));
//
//            payload.put("authorizedServices", authServices);
//            payload.put("validTo", "1971-09-09T23:00:00.000Z");
//            payload.put("validFrom", "1971-09-09T22:00:00.000Z");
//            payload.put("certid", selectedRemoteCredentials.getCertId());
//
//            revokeKey.put(payload);
//            revokeKeyOuter.put(revokeKey);
//
//            Log.d("REVOKE_OLD", revokeKey.toString());

            /* New code */
//            UserCredentials revokingCredentials = new UserCredentials();

            //revokingUser.setCertId(selectedRemoteCredentials.getCertId()); // TODO: Probably should set the vehicle or something here

            User user = ServerNode.getUserData();
            Integer selectedVehicleIndex = user.getSelectedVehicleIndex();
            Vehicle vehicle = (selectedVehicleIndex != -1) ? user.getVehicles().get(selectedVehicleIndex) : new Vehicle(); // TODO: Will always be valid so long as we always go back to last screen when new user data is available

            // TODO: If new user data comes in and vehicle list changes, need to get out of here or bugs

            Vehicle revokingVehicle = new Vehicle(vehicle.getVehicleId());

            revokingUser.addVehicle(revokingVehicle);


            Log.d("REVOKE_NEW", revokingUser.toString());

        } catch (Exception e) { e.printStackTrace(); }

        return revokingUser;//revokeKey;
    }

    public void addUsers(RemoteCredentialsAdapter adapter){
        try {
            //ArrayList<UserCredentials> remoteCredentialsList = new ArrayList<>(ServerNode.getRemoteCredentialsList());
            ArrayList<User> guestUsers = ServerNode.getUserData().getGuests();

            adapter.addAll(guestUsers);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_key_change, menu);
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
}
