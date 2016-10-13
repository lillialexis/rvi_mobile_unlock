package com.jaguarlandrover.pki;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * Copyright (c) 2016 Jaguar Land Rover.
 *
 * This program is licensed under the terms and conditions of the
 * Mozilla Public License, version 2.0. The full text of the
 * Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
 *
 * File:    ProvisioningServerResponse.java
 * Project: UnlockDemo
 *
 * Created by Lilli Szafranski on 10/13/16.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

import com.google.gson.annotations.SerializedName;

import java.security.KeyStore;
import java.util.ArrayList;

public class PKIServerResponse {
    private final static String TAG = "UnlockDemo/ProvSrvrResp";

    @SerializedName("status")
    private String mStatus = "unknown";

    public enum Status {
        UNKNOWN,
        ERROR,
        VERIFICATION_NEEDED,
        CERTIFICATE_RESPONSE
    }

    public PKIServerResponse() {
    }

    public Status getStatus() {
        switch (mStatus) {
            case "error":
                return Status.ERROR;
            case "verification_needed":
                return Status.VERIFICATION_NEEDED;
            case "certificate_response":
                return Status.CERTIFICATE_RESPONSE;
        }

        return Status.UNKNOWN;
    }

    protected void setStatus(String status) {
        mStatus = status;
    }
}

