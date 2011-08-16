/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.commands.sendbug;

import android.accounts.Account;
import android.accounts.IAccountManager;
import android.app.ActivityManagerNative;
import android.app.IActivityManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;

import java.io.File;

public class SendBug {

    private static final String GOOGLE_ACCOUNT_TYPE = "com.google";
    private static final String EMAIL_ACCOUNT_TYPE = "com.android.email";

    public static void main(String[] args) {
        if (args.length >= 1) {
            new SendBug().run(args[0]);
        }
    }

    private void run(String bugreportPath) {
        File bugreport = new File(bugreportPath);
        if (bugreport.exists()) {
            Account sendToAccount = findSendToAccount();
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.setType("application/octet-stream");
            intent.putExtra("subject", bugreport.getName());
            StringBuilder sb = new StringBuilder();
            sb.append(SystemProperties.get("ro.build.description"));
            sb.append("\n(Sent from BugMailer)");
            intent.putExtra("body", sb.toString());
            intent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(bugreport));
            if (sendToAccount != null) {
                intent.putExtra("to", sendToAccount.name);
            }
            IActivityManager mAm = ActivityManagerNative.getDefault();
            try {
                mAm.startActivity(null, intent, intent.getType(), null, 0, null, null, 0, false,
                        false, null, null, false);
            } catch (RemoteException e) {
            }
        }
    }

    private Account findSendToAccount() {
        IAccountManager accountManager = IAccountManager.Stub.asInterface(ServiceManager
                .getService(Context.ACCOUNT_SERVICE));
        Account[] accounts = null;
        Account foundAccount = null;
        try {
            accounts = accountManager.getAccounts(null);
        } catch (RemoteException e) {
        }
        if (accounts != null) {
            for (Account account : accounts) {
                if (GOOGLE_ACCOUNT_TYPE.equals(account.type)) {
                    // return first gmail account found
                    return account;
                } else if (EMAIL_ACCOUNT_TYPE.equals(account.type)) {
                    // keep regular email account for now in case there are gmail accounts
                    // found later
                    foundAccount = account;
                }
            }
        }
        return foundAccount;
    }
}
