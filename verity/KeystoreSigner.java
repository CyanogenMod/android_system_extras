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
import java.security.PublicKey;
import java.security.Signature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * AndroidVerifiedBootKeystore DEFINITIONS ::=
 * BEGIN
 *     FormatVersion ::= INTEGER
 *     KeyBag ::= SEQUENCE {
 *         Key  ::= SEQUENCE {
 *             AlgorithmIdentifier  ::=  SEQUENCE {
 *                 algorithm OBJECT IDENTIFIER,
 *                 parameters ANY DEFINED BY algorithm OPTIONAL
 *             }
 *             KeyMaterial ::= RSAPublicKey
 *         }
 *     }
 *     Signature ::= AndroidVerifiedBootSignature
 * END
 */

class BootKey extends ASN1Object
{
    private AlgorithmIdentifier algorithmIdentifier;
    private RSAPublicKey keyMaterial;

    public BootKey(PublicKey key) throws Exception {
        java.security.interfaces.RSAPublicKey k =
                (java.security.interfaces.RSAPublicKey) key;
        this.keyMaterial = new RSAPublicKey(
                k.getModulus(),
                k.getPublicExponent());
        this.algorithmIdentifier = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(algorithmIdentifier);
        v.add(keyMaterial);
        return new DERSequence(v);
    }

    public void dump() throws Exception {
        System.out.println(ASN1Dump.dumpAsString(toASN1Primitive()));
    }
}

class BootKeystore extends ASN1Object
{
    private ASN1Integer                     formatVersion;
    private ASN1EncodableVector             keyBag;
    private BootSignature    signature;

    public BootKeystore() {
        this.formatVersion = new ASN1Integer(0);
        this.keyBag = new ASN1EncodableVector();
    }

    public void addPublicKey(byte[] der) throws Exception {
        PublicKey pubkey = Utils.loadDERPublicKey(der);
        BootKey k = new BootKey(pubkey);
        keyBag.add(k);
    }

    public byte[] getInnerKeystore() throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(formatVersion);
        v.add(new DERSequence(keyBag));
        return new DERSequence(v).getEncoded();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(formatVersion);
        v.add(new DERSequence(keyBag));
        v.add(signature);
        return new DERSequence(v);
    }

    public void sign(PrivateKey privateKey) throws Exception {
        byte[] innerKeystore = getInnerKeystore();
        byte[] rawSignature = Utils.sign(privateKey, innerKeystore);
        signature = new BootSignature("keystore", innerKeystore.length);
        signature.setSignature(rawSignature);
    }

    public void dump() throws Exception {
        System.out.println(ASN1Dump.dumpAsString(toASN1Primitive()));
    }

    // USAGE:
    //      AndroidVerifiedBootKeystoreSigner <privkeyFile> <outfile> <pubkeyFile0> ... <pubkeyFileN-1>
    // EG:
    //     java -cp ../../../out/host/common/obj/JAVA_LIBRARIES/AndroidVerifiedBootKeystoreSigner_intermediates/classes/ com.android.verity.AndroidVerifiedBootKeystoreSigner ../../../build/target/product/security/verity_private_dev_key /tmp/keystore.out /tmp/k
    public static void main(String[] args) throws Exception {
        String privkeyFname = args[0];
        String outfileFname = args[1];
        BootKeystore ks = new BootKeystore();
        for (int i=2; i < args.length; i++) {
            ks.addPublicKey(Utils.read(args[i]));
        }
        ks.sign(Utils.loadPEMPrivateKeyFromFile(privkeyFname));
        Utils.write(ks.getEncoded(), outfileFname);
    }
}