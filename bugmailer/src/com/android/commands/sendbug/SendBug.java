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
import android.content.pm.IPackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SendBug {

    private static final String LOG_TAG = SendBug.class.getSimpleName();
    private static final Pattern EMAIL_REGEX = Pattern.compile(
            "^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$");
    private static final String SEND_BUG_INTENT_ACTION = "android.testing.SEND_BUG";

    public static void main(String[] args) {
        if (args.length == 1) {
            new SendBug().run(args[0]);
        } else if (args.length == 2) {
            new SendBug().run(args[0], args[1]);
        }
    }

    private void run(String bugreportPath) {
        run(bugreportPath, null);
    }

    private void run(String bugreportPath, String screenShotPath) {
        final File bugreport = new File(bugreportPath);
        File screenShot = null;
        if (screenShotPath != null) {
            screenShot = new File(screenShotPath);
        }
        final Uri bugreportUri = Uri.fromFile(bugreport);
        // todo (aalbert): investigate adding a screenshot to BugReporter
        Intent intent = tryBugReporter(bugreportUri);
        if (intent == null) {
            final Uri screenshotUri = screenShot != null
                    ? Uri.fromFile(screenShot) : null;
            intent = getSendMailIntent(bugreportUri, screenshotUri);
        }
        if (intent != null) {
            final IActivityManager am = ActivityManagerNative.getDefault();
            if (am == null) {
                Log.e(LOG_TAG, "Cannot get ActivityManager, is the system running?");
                return;
            }
            try {
                am.startActivityAsUser(null, intent, intent.getType(), null, null, 0, 0,
                        null, null, null, UserHandle.USER_CURRENT);
            } catch (RemoteException e) {
                // ignore
            }
        } else {
            Log.w(LOG_TAG, "Cannot find account to send bugreport, local path: "
                    + bugreportPath);
        }
    }

    private Intent tryBugReporter(Uri bugreportUri) {
        final Intent intent = new Intent(SEND_BUG_INTENT_ACTION);
        intent.setData(bugreportUri);
        final IPackageManager pm = IPackageManager.Stub.asInterface(
                ServiceManager.getService("package"));
        if (pm == null) {
            Log.e(LOG_TAG, "Cannot get PackageManager, is the system running?");
            return null;
        }
        final List<ResolveInfo> results;
        try {
            results = pm.queryIntentActivities(intent, null, 0, 0);
        } catch (RemoteException e) {
            return null;
        }
        if (results != null && results.size() > 0) {
            final ResolveInfo info = results.get(0);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.setClassName(info.activityInfo.applicationInfo.packageName,
                    info.activityInfo.name);
            return intent;
        } else {
            return null;
        }
    }

    private Intent getSendMailIntent(Uri bugreportUri, Uri screenshotUri) {
        final Account sendToAccount = findSendToAccount();
        final Intent intent = new Intent(Intent.ACTION_SEND);
        intent.addCategory(Intent.CATEGORY_DEFAULT);
        intent.setType("application/octet-stream");
        intent.putExtra(Intent.EXTRA_SUBJECT, bugreportUri.getLastPathSegment());
        final StringBuilder sb = new StringBuilder();
        sb.append(SystemProperties.get("ro.build.description"));
        sb.append("\n(Sent from BugMailer)");
        intent.putExtra(Intent.EXTRA_TEXT, (CharSequence)sb);
        if (screenshotUri != null) {
            final ArrayList<Uri> attachments = new ArrayList<Uri>();
            attachments.add(bugreportUri);
            attachments.add(screenshotUri);
            intent.setAction(Intent.ACTION_SEND_MULTIPLE);
            intent.putParcelableArrayListExtra(Intent.EXTRA_STREAM, attachments);
        } else {
            intent.putExtra(Intent.EXTRA_STREAM, bugreportUri);
        }
        if (sendToAccount != null) {
            intent.putExtra(Intent.EXTRA_EMAIL, new String[]{sendToAccount.name});
            return intent;
        }
        return null;
    }

    private Account findSendToAccount() {
        final IAccountManager accountManager = IAccountManager.Stub.asInterface(ServiceManager
                .getService(Context.ACCOUNT_SERVICE));
        if (accountManager == null) {
            Log.e(LOG_TAG, "Cannot get AccountManager, is the system running?");
            return null;
        }
        Account[] accounts = null;
        Account foundAccount = null;
        String preferredDomain = SystemProperties.get("sendbug.preferred.domain");
        if (!preferredDomain.startsWith("@")) {
            preferredDomain = "@" + preferredDomain;
        }
        try {
            accounts = accountManager.getAccounts(null);
        } catch (RemoteException e) {
            // ignore
        }
        if (accounts != null) {
            for (Account account : accounts) {
                if (EMAIL_REGEX.matcher(account.name).matches()) {
                    if (!preferredDomain.isEmpty()) {
                        // if we have a preferred domain and it matches, return; otherwise keep
                        // looking
                        if (account.name.endsWith(preferredDomain)) {
                            return account;
                        } else {
                            foundAccount = account;
                        }
                        // if we don't have a preferred domain, just return since it looks like
                        // an email address
                    } else {
                        return account;
                    }
                }
            }
        }
        return foundAccount;
    }
}
