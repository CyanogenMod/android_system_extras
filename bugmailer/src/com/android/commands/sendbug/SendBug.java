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
import android.os.Environment;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;

import java.io.File;
import java.io.FilenameFilter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SendBug {

    private static final String GOOGLE_ACCOUNT_TYPE = "com.google";
    private static final String EMAIL_ACCOUNT_TYPE = "com.android.email";
    private static final String SEND_BUG_INTENT_ACTION = "android.testing.SEND_BUG";

    private static final Pattern datePattern = Pattern.compile(
            ".*(\\d\\d\\d\\d[-_.]\\d\\d[-_.]\\d\\d[-_.]\\d\\d[-_.]\\d\\d[-_.]\\d\\d).*");
    private static final File screenshotDir = new File(
            Environment.getExternalStorageDirectory() + "/Pictures/Screenshots");
    private static final long MAX_SCREENSHOT_AGE_MS = 5 * 50 * 1000;

    public static void main(String[] args) {
        if (args.length >= 1) {
            new SendBug().run(args[0]);
        }
    }

    private void run(String bugreportPath) {
        final File bugreport = new File(bugreportPath);
        if (bugreport.exists()) {
            final Uri bugreportUri = Uri.fromFile(bugreport);
            // todo (aalbert): investigate adding a screenshot to BugReporter
            Intent intent = tryBugReporter(bugreportUri);
            if (intent == null) {
                final File screenshotFile = findScreenshotFile(bugreportPath);
                final Uri screenshotUri = screenshotFile != null
                        ? Uri.fromFile(screenshotFile) : null;
                intent = getSendMailIntent(bugreportUri, screenshotUri);
            }
            final IActivityManager mAm = ActivityManagerNative.getDefault();
            try {
                mAm.startActivity(null, intent, intent.getType(), null, 0, null, null, 0, false,
                        false, null, null, false);
            } catch (RemoteException e) {
                // ignore
            }
        }
    }

    private Intent tryBugReporter(Uri bugreportUri) {
        final Intent intent = new Intent(SEND_BUG_INTENT_ACTION);
        intent.setData(bugreportUri);
        final IPackageManager mPm = IPackageManager.Stub.asInterface(
                ServiceManager.getService("package"));
        if (mPm != null) {
            final List<ResolveInfo> results;
            try {
                results = mPm.queryIntentActivities(intent, null, 0);
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
        return null;
    }

    private Intent getSendMailIntent(Uri bugreportUri, Uri screenshotUri) {
        final Account sendToAccount = findSendToAccount();
        final Intent intent = new Intent(Intent.ACTION_SEND);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.setType("application/octet-stream");
        intent.putExtra("subject", bugreportUri.getLastPathSegment());
        final StringBuilder sb = new StringBuilder();
        sb.append(SystemProperties.get("ro.build.description"));
        sb.append("\n(Sent from BugMailer)");
        intent.putExtra("body", sb.toString());
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
            intent.putExtra("to", sendToAccount.name);
        }
        return intent;
    }

    private Account findSendToAccount() {
        final IAccountManager accountManager = IAccountManager.Stub.asInterface(ServiceManager
                .getService(Context.ACCOUNT_SERVICE));
        Account[] accounts = null;
        Account foundAccount = null;
        try {
            accounts = accountManager.getAccounts(null);
        } catch (RemoteException e) {
            // ignore
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

    // Try to find a screenshot that was taken shortly before this bugreport was.
    private File findScreenshotFile(String bugreportPath) {
        final Date bugreportDate = getDate(bugreportPath);
        if (bugreportDate == null) {
            return null;
        }

        final String[] screenshotFiles = screenshotDir.list(
                new FilenameFilter() {
                    private final Pattern pattern = Pattern.compile("[Ss]creenshot.*\\.png");

                    public boolean accept(File dir, String filename) {
                        return pattern.matcher(filename).matches();
                    }
                });
        long minDiff = Long.MAX_VALUE;
        String bestMatch = null;
        for (String screenshotFile : screenshotFiles) {
            final Date date = getDate(screenshotFile);
            if (date == null) {
                continue;
            }
            final long diff = bugreportDate.getTime() - date.getTime();
            if (diff < minDiff) {
                minDiff = diff;
                bestMatch = screenshotFile;
            }
        }

        if (minDiff < MAX_SCREENSHOT_AGE_MS) {
            return new File(screenshotDir, bestMatch);
        }

        return null;
    }

    private static Date getDate(final String string) {
        final Matcher matcher = datePattern.matcher(string);
        if (!matcher.matches()) {
            return null;
        }
        final String dateString = matcher.group(1);
        final char sep1 = dateString.charAt(4);
        final char sep2 = dateString.charAt(7);
        final char sep3 = dateString.charAt(10);
        final char sep4 = dateString.charAt(13);
        final char sep5 = dateString.charAt(16);
        final SimpleDateFormat format = new SimpleDateFormat(
                "yyyy" + sep1 + "MM" + sep2 + "dd" + sep3 + "HH" + sep4 + "mm" + sep5 + "ss");
        try {
            return format.parse(dateString);
        } catch (ParseException e) {
            return null;
        }
    }
}
