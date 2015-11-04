/**
 *  Copyright (C) 2015, Jaguar Land Rover
 *
 *  This program is licensed under the terms and conditions of the
 *  Mozilla Public License, version 2.0.  The full text of the
 *  Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
 *
 */

package com.jaguarlandrover.auto.remote.vehicleentry;

import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

public abstract class RviProtocol {
    private static final String TAG = "RVI";

    public enum RviTransport {SERVER, BT} //NFC,WIFI DIRECT, IR

    public abstract InputStream getInputStream() throws IOException;
    public abstract OutputStream getOutputStream() throws IOException;

    //Helper static protocol wire functions

    public static JSONObject parseData(String data) throws JSONException {
        byte[] jsonBuff = Base64.decode(data,Base64.DEFAULT);
        String jsonStr = new String(jsonBuff);
        return new JSONObject(jsonStr);
    }

    //{"tid":1,"cmd":"au","addr":"127.0.0.1","port":8807,"ver":"1.0","cert":"","sign":"" }
    public static JSONObject createAuth(int tid, String addr, int port, String cert, String sig) throws JSONException {
        JSONObject auth = new JSONObject();
        auth.put("tid", tid);
        auth.put("cmd", "au");
        auth.put("addr", addr);
        auth.put("port", port);
        auth.put("ver", "1.0");
        auth.put("certificate", cert);
        auth.put("signature", sig);
        return auth;
    }


    //{"tid":1,"cmd":"rcv","mod":"proto_json_rpc","data":"eyJzZXJ2aWNlIjoiamxyLmNvbS9idC9zdG9mZmUvbG9jayIsInRpbWVvdXQiOjE
    //0MzQwNTMyNTkwMDAsInBhcmFtZXRlcnMiOlt7ImEiOiJiIn1dLCJzaWduYXR1cmUiOiJzaWduYXR1cmUiLCJjZXJ0aWZpY2F
    //0ZSI6ImNlcnRpZmljYXRlIn0="}
    //
    // Decoded
    // {"service":"jlr.com/bt/stoffe/lock","timeout":1434053259000,"parameters":[{"a":"b"}],"signature":"signature","certificate":"certificate"}

    public static JSONObject createReceiveData(int tid, String service, JSONArray params, String cert, String sig) throws JSONException {
        JSONObject payload = new JSONObject();
        payload.put("service", service);
        payload.put("timeout", System.currentTimeMillis() + 20000); //TODO
        payload.put("parameters", params);
        payload.put("certificate", cert);
        payload.put("signature", sig);

        JSONObject rcvData = new JSONObject();
        rcvData.put("tid", tid);
        rcvData.put("cmd", "rcv");

        rcvData.put("mod", "proto_json_rpc");
        String enc = Base64.encodeToString(payload.toString().getBytes(), 0);
        rcvData.put("data", enc);

        Log.d(TAG, "rcv : " + rcvData.toString());
        return rcvData;
    }

    public static JSONObject createRequestData(int tid, String service, JSONObject params, String cert, String sig) throws JSONException {
        JSONObject payload = new JSONObject();
        payload.put("service", service);
        payload.put("timeout", System.currentTimeMillis() + 20000); //TODO
        payload.put("parameters", params);
        payload.put("certificate", cert);
        payload.put("signature", sig);

        JSONObject rcvData = new JSONObject();
        rcvData.put("tid", tid);
        rcvData.put("cmd", "rcv");

        rcvData.put("mod", "proto_json_rpc");
        String enc = Base64.encodeToString(payload.toString().getBytes(), 0);
        rcvData.put("data", enc);

        Log.d(TAG, "rcv : " + rcvData.toString());
        return rcvData;
    }


    //{"sign": "","cmd": "sa","tid": 1,"svcs": ["jlr.com\/bt\/stoffe\/unlock","jlr.com\/bt\/stoffe\/unlock:lock"],"stat": "av"}
    public static JSONObject createServiceAnnouncement(int tid, String[] services, String stat, String cert, String sig) throws JSONException {
        JSONObject sa = new JSONObject();

        sa.put("tid", tid);
        sa.put("cmd", "sa");
        sa.put("stat", stat);
        List<String> l = Arrays.asList(services);
        Log.e(TAG," Col="+l.size()+" JArray = "+new JSONArray(l));
        sa.put("svcs", new JSONArray(l));
        sa.put("certificate", cert);
        sa.put("signature", sig);

        Log.d(TAG, "sa : " + sa.toString());
        return sa;
    }

    //{"cmd": "ping"}

    public static String[] parseAndValidateJWT( String encToken ) {
        String[] result = new String[3];

        String [] jwtParts = encToken.split("\\.");
        if( jwtParts[0] != null ) result[0] = new String(Base64.decode(jwtParts[0],Base64.URL_SAFE));
        if( jwtParts[1] != null ) result[1] = new String(Base64.decode(jwtParts[1],Base64.URL_SAFE));
        if( jwtParts[2] != null ) result[2] = new String(Base64.decode(jwtParts[2],Base64.URL_SAFE));

        //TODO validate, maybe also just return JSONObject?

        return result;
    }
}
