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

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *    AndroidVerifiedBootSignature DEFINITIONS ::=
 *    BEGIN
 *        FormatVersion ::= INTEGER
 *        AlgorithmIdentifier ::=  SEQUENCE {
 *            algorithm OBJECT IDENTIFIER,
 *            parameters ANY DEFINED BY algorithm OPTIONAL
 *        }
 *        AuthenticatedAttributes ::= SEQUENCE {
 *            target CHARACTER STRING,
 *            length INTEGER
 *        }
 *        Signature ::= OCTET STRING
 *     END
 */

public class BootSignature extends ASN1Object
{
    private ASN1Integer             formatVersion;
    private AlgorithmIdentifier     algorithmIdentifier;
    private DERPrintableString      target;
    private ASN1Integer             length;
    private DEROctetString          signature;

    public BootSignature(String target, int length) {
        this.formatVersion = new ASN1Integer(0);
        this.target = new DERPrintableString(target);
        this.length = new ASN1Integer(length);
        this.algorithmIdentifier = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    public ASN1Object getAuthenticatedAttributes() {
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(target);
        attrs.add(length);
        return new DERSequence(attrs);
    }

    public byte[] getEncodedAuthenticatedAttributes() throws IOException {
        return getAuthenticatedAttributes().getEncoded();
    }

    public void setSignature(byte[] sig) {
        signature = new DEROctetString(sig);
    }

    public byte[] generateSignableImage(byte[] image) throws IOException {
        byte[] attrs = getEncodedAuthenticatedAttributes();
        byte[] signable = Arrays.copyOf(image, image.length + attrs.length);
        for (int i=0; i < attrs.length; i++) {
            signable[i+image.length] = attrs[i];
        }
        return signable;
    }

    public byte[] sign(byte[] image, PrivateKey key) throws Exception {
        byte[] signable = generateSignableImage(image);
        byte[] signature = Utils.sign(key, signable);
        byte[] signed = Arrays.copyOf(image, image.length + signature.length);
        for (int i=0; i < signature.length; i++) {
            signed[i+image.length] = signature[i];
        }
        return signed;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(formatVersion);
        v.add(algorithmIdentifier);
        v.add(getAuthenticatedAttributes());
        v.add(signature);
        return new DERSequence(v);
    }

    public static void doSignature( String target,
                                    String imagePath,
                                    String keyPath,
                                    String outPath) throws Exception {
        byte[] image = Utils.read(imagePath);
        BootSignature bootsig = new BootSignature(target, image.length);
        PrivateKey key = Utils.loadPEMPrivateKeyFromFile(keyPath);
        byte[] signature = bootsig.sign(image, key);
        Utils.write(signature, outPath);
    }

    // java -cp ../../../out/host/common/obj/JAVA_LIBRARIES/AndroidVerifiedBootSigner_intermediates/classes/ com.android.verity.AndroidVerifiedBootSigner boot ../../../out/target/product/flounder/boot.img ../../../build/target/product/security/verity_private_dev_key /tmp/boot.img.signed
    public static void main(String[] args) throws Exception {
        doSignature(args[0], args[1], args[2], args[3]);
    }
}