package com.westernacher.cri;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;

import static java.lang.String.format;

public class CertReqInfoGenerator {
    public static void generate(String pubKeyFile, String x500Name, String outputFile) throws IOException {
        if (!new File(pubKeyFile).canRead()) {
            System.err.println(format("Cannot read file %s.", pubKeyFile));
            return;
        }

        ASN1Primitive object;
        try {
            ASN1InputStream asn1InputStream = new ASN1InputStream(new FileInputStream(pubKeyFile));
            object = asn1InputStream.readObject();
        } catch (IOException e) {
            // try PEM as a fallback
            System.out.println("Failed to read DER file - try to fallback to PEM format.");
            final PemReader pemReader = new PemReader(new FileReader(pubKeyFile));
            final byte[] pemContent = pemReader.readPemObject().getContent();
            ASN1InputStream asn1InputStream = new ASN1InputStream(pemContent);
            object = asn1InputStream.readObject();
        }
        new CertReqInfoGenerator().newRequestInfo(object.getEncoded(), x500Name, outputFile);
        System.out.printf("CertificationRequestInfo written to file %s%n", outputFile);
    }

    private void newRequestInfo(byte[] publicKey, String x500Name, String outputFile) throws IOException {
        final SubjectPublicKeyInfo publicKeyInfo = subjectPublicKeyInfo(publicKey);
        final X500Name x500 = new X500Name(x500Name);
        final ASN1Set attributes = new DERSet();
        final CertificationRequestInfo requestInfo = new CertificationRequestInfo(x500, publicKeyInfo, attributes);
        try (final OutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(requestInfo.getEncoded());
        }
    }

    /**
     * Convert the public key into a {@link SubjectPublicKeyInfo} object.
     * Handles incomplete key data as well by assuming that the byte array contains RSA public key data only.
     */
    private SubjectPublicKeyInfo subjectPublicKeyInfo(byte[] publicKey) {
        try {
            return SubjectPublicKeyInfo.getInstance(publicKey);
        } catch (IllegalArgumentException e) {
            System.err.println("Public key is incomplete. Assuming RSA public key material.");
            final ASN1ObjectIdentifier rsaIdentifier = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");
            final ASN1EncodableVector idPartVector = new ASN1EncodableVector();
            idPartVector.add(rsaIdentifier);
            idPartVector.add(DERNull.INSTANCE);
            final ASN1Sequence idPart = new DERSequence(idPartVector);
            final DERBitString keyPart = new DERBitString(publicKey);
            final ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(idPart);
            vector.add(keyPart);
            final DERSequence pubkeySequence = new DERSequence(vector);
            return SubjectPublicKeyInfo.getInstance(pubkeySequence);
        }
    }
}
