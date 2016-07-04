package com.westernacher.asn1;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.X509CertStoreSelector;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

public class VerifyTST {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static PrintStream out = System.out;

    private TimeStampToken token;
    private X509Certificate certificate;
    private byte[] digest;

    public byte[] getDigest() {
        return digest;
    }

    public VerifyTST(TimeStampToken token, X509Certificate certificate) {
        this.token = token;
        this.certificate = certificate;
    }

    public void verify() {
        if (certificate != null) {
            try {
                validate();
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new RuntimeException(e);
                }
            }
        } else {
            out.println("timestamp not validated without certificate");
        }

        Store store = token.getCertificates();
        out.println("certs = " + store.getMatches(new X509CertStoreSelector()));
        if (token.getSignedAttributes() != null) {
            out.println("signed attribute count: " + token.getSignedAttributes().size());
            @SuppressWarnings("unchecked")
            Hashtable<ASN1ObjectIdentifier, org.bouncycastle.asn1.cms.Attribute> attributes = token.getSignedAttributes().toHashtable();
            for (ASN1ObjectIdentifier key : attributes.keySet()) {
                final String oid = key.getId();
                out.println("oid = " + oid + " (" + OidProperties.resolveOid(oid) + ")");
                for (ASN1Encodable value : attributes.get(key).getAttributeValues()) {
                    out.println("    value");
                    if (key.getId().equals("1.2.840.113549.1.9.16.2.18")) {
                        ASN1Sequence sequence = (ASN1Sequence) value.toASN1Primitive();
                        for (int i = 0; i < sequence.size(); i++) {
                            ASN1TaggedObject object = (ASN1TaggedObject) sequence.getObjectAt(i);
                            if (object.getTagNo() == 1) {
                                try {
                                    IOUtils.write(object.getObject().getEncoded(), new FileOutputStream("/tmp/attr-cert.der"));
                                    X509AttributeCertificateHolder attrHolder = new X509AttributeCertificateHolder(object.getObject().getEncoded());
                                    out.println("        attribute certificate from issuer " + attrHolder.getIssuer().getNames()[0] + " saved to /tmp/attr-cert.der");
                                    for (org.bouncycastle.asn1.x509.Attribute attribute : attrHolder.getAttributes()) {
                                        String attrOid = attribute.getAttrType().getId();
                                        out.println("            attribute: " + attrOid + " (" + OidProperties.resolveOid(attrOid) + ")");
                                        //									new Asn1Parser(attribute.getAttrValues(), 4).print();
                                    }
                                } catch (IOException e) {
                                    throw new RuntimeException(e);
                                }
                            } else {
                                out.println("        tagged object #" + object.getTagNo());
//								new Asn1Parser(value.toASN1Primitive(), 3).print();
                            }
                        }
                    } else {
                        new Asn1Parser(value.toASN1Primitive(), 2).print();
                    }
                }
            }
            out.println("signed attribute count: " + attributes.size());
        } else {
            out.println("no unsigned attributes");
        }
        if (token.getUnsignedAttributes() != null) {
            out.println("unsigned attribute count: " + token.getUnsignedAttributes().size());
        } else {
            out.println("no unsigned attributes");
        }

        TimeStampTokenInfo tsti = token.getTimeStampInfo();
        out.println("TSA: " + tsti.getTsa());
        String oid = tsti.getPolicy().getId();
        out.println("policy: " + oid + " (" + OidProperties.resolveOid(oid) + ")");
        out.println("serial: " + tsti.getSerialNumber());
        oid = tsti.getMessageImprintAlgOID().getId();
        out.println("imprint algorithm: " + oid + " (" + OidProperties.resolveOid(oid) + ")");
        oid = tsti.getHashAlgorithm().getAlgorithm().getId();
        out.println("hash algorithm: " + oid + " (" + OidProperties.resolveOid(oid) + ")");
        out.println("time stamp: " + tsti.getGenTime());

        GenTimeAccuracy gta = tsti.getGenTimeAccuracy();
        out.println("accuracy: " + gta.getSeconds() + " s, " + gta.getMillis() + " ms, " + gta.getMicros() + " us");

        digest = tsti.getMessageImprintDigest();
    }

    private void validate() throws OperatorException, CMSException {
        final SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate);
        try {
            token.validate(verifier);
            out.println("timestamp successfully validated");
        } catch (Exception e) {
            out.println("ERROR: validation failed");
            final SignerInformation signerInformation = token.toCMSSignedData().getSignerInfos().get(token.getSID());
            if (signerInformation.verify(verifier)) {
                System.out.println("    CMS level successfully validated");
            } else {
                System.out.println("    CMS level validation failed");
            }
        }
    }
}
