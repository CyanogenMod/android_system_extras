/*
 * Copyright (C) 2014 The Android Open Source Project
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

package com.android.verity;

import java.lang.reflect.Constructor;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.util.encoders.Base64;

public class Utils {

    private static void loadProviderIfNecessary(String providerClassName) {
        if (providerClassName == null) {
            return;
        }

        final Class<?> klass;
        try {
            final ClassLoader sysLoader = ClassLoader.getSystemClassLoader();
            if (sysLoader != null) {
                klass = sysLoader.loadClass(providerClassName);
            } else {
                klass = Class.forName(providerClassName);
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            System.exit(1);
            return;
        }

        Constructor<?> constructor = null;
        for (Constructor<?> c : klass.getConstructors()) {
            if (c.getParameterTypes().length == 0) {
                constructor = c;
                break;
            }
        }
        if (constructor == null) {
            System.err.println("No zero-arg constructor found for " + providerClassName);
            System.exit(1);
            return;
        }

        final Object o;
        try {
            o = constructor.newInstance();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return;
        }
        if (!(o instanceof Provider)) {
            System.err.println("Not a Provider class: " + providerClassName);
            System.exit(1);
        }

        Security.insertProviderAt((Provider) o, 1);
    }

    static byte[] pemToDer(String pem) throws Exception {
        pem = pem.replaceAll("^-.*", "");
        String base64_der = pem.replaceAll("-.*$", "");
        return Base64.decode(base64_der);
    }

    static PrivateKey loadDERPrivateKey(byte[] der) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(der);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (PrivateKey) keyFactory.generatePrivate(keySpec);
    }

    static PrivateKey loadPEMPrivateKey(byte[] pem) throws Exception {
        byte[] der = pemToDer(new String(pem));
        return loadDERPrivateKey(der);
    }

    static PrivateKey loadPEMPrivateKeyFromFile(String keyFname) throws Exception {
        return loadPEMPrivateKey(read(keyFname));
    }

    static PrivateKey loadDERPrivateKeyFromFile(String keyFname) throws Exception {
        return loadDERPrivateKey(read(keyFname));
    }

    static PublicKey loadDERPublicKey(byte[] der) throws Exception {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(der);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(publicKeySpec);
    }

    static PublicKey loadPEMPublicKey(byte[] pem) throws Exception {
        byte[] der = pemToDer(new String(pem));
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(der);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(publicKeySpec);
    }

    static PublicKey loadPEMPublicKeyFromFile(String keyFname) throws Exception {
        return loadPEMPublicKey(read(keyFname));
    }

    static PublicKey loadDERPublicKeyFromFile(String keyFname) throws Exception {
        return loadDERPublicKey(read(keyFname));
    }

    static byte[] sign(PrivateKey privateKey, byte[] input) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(privateKey);
        signer.update(input);
        return signer.sign();
    }

    static byte[] read(String fname) throws Exception {
        long offset = 0;
        File f = new File(fname);
        long length = f.length();
        byte[] image = new byte[(int)length];
        FileInputStream fis = new FileInputStream(f);
        while (offset < length) {
            offset += fis.read(image, (int)offset, (int)(length - offset));
        }
        fis.close();
        return image;
    }

    static void write(byte[] data, String fname) throws Exception{
        FileOutputStream out = new FileOutputStream(fname);
        out.write(data);
        out.close();
    }
}