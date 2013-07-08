/*
 * Copyright (C) 2013 The Android Open Source Project
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

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

class VeritySigner {

    private static byte[] sign(PrivateKey privateKey, byte[] input) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(privateKey);
        signer.update(input);
        return signer.sign();
    }

    private static PKCS8EncodedKeySpec pemToDer(String pem) throws Exception {
        pem = pem.replaceAll("^-.*", "");
        String base64_der = pem.replaceAll("-.*$", "");
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] der = decoder.decodeBuffer(base64_der);
        return new PKCS8EncodedKeySpec(der);
    }

    private static PrivateKey loadPrivateKey(String pem) throws Exception {
        PKCS8EncodedKeySpec keySpec = pemToDer(pem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (PrivateKey) keyFactory.generatePrivate(keySpec);
    }

    private static byte[] read(String path) throws Exception {
        File contentFile = new File(path);
        byte[] content = new byte[(int)contentFile.length()];
        FileInputStream fis = new FileInputStream(contentFile);
        fis.read(content);
        fis.close();
        return content;
    }

    private static void writeOutput(String path, byte[] output) throws Exception {
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(output);
        fos.close();
    }

    // USAGE:
    //     VeritySigner <contentfile> <key.pem> <sigfile>
    // To verify that this has correct output:
    //     openssl rsautl -raw -inkey <key.pem> -encrypt -in <sigfile> > /tmp/dump
    public static void main(String[] args) throws Exception {
        byte[] content = read(args[0]);
        PrivateKey privateKey = loadPrivateKey(new String(read(args[1])));
        byte[] signature = sign(privateKey, content);
        writeOutput(args[2], signature);
    }
}
