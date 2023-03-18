package xyz.its_me.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Map;

public class VerifyTST {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final TimeStampToken token;
    private final X509Certificate certificate;
    private byte[] digest;

    public byte[] getDigest() {
        return digest;
    }

    public VerifyTST(TimeStampToken token, X509Certificate certificate) {
        this.token = token;
        this.certificate = certificate;
    }

    public void verify() {
        validateCertificate();

        Store<X509CertificateHolder> store = token.getCertificates();
        logger.info("certs = {}", store.getMatches(null));
        if (token.getSignedAttributes() != null) {
            logger.info("signed attribute count: {}", token.getSignedAttributes().size());
            @SuppressWarnings("unchecked")
            Hashtable<ASN1ObjectIdentifier, org.bouncycastle.asn1.cms.Attribute> attributes = token.getSignedAttributes().toHashtable();
            for (Map.Entry<ASN1ObjectIdentifier, Attribute> entry : attributes.entrySet()) {
                final String oid = entry.getKey().getId();
                logger.info("oid = {} ({})", oid, OidProperties.resolveOid(oid));
                Arrays.stream(entry.getValue().getAttributeValues()).forEach(attributeValue -> {
                    logger.info("    value");
                    if (entry.getKey().getId().equals("1.2.840.113549.1.9.16.2.18")) {
                        ASN1Sequence sequence = (ASN1Sequence) attributeValue.toASN1Primitive();
                        sequence.forEach(this::verifySignerAttribute);
                    } else {
                        new Asn1Parser(attributeValue.toASN1Primitive(), 2).print();
                    }
                });
            }
            logger.info("signed attribute count: {}", attributes.size());
        } else {
            logger.info("no unsigned attributes");
        }
        if (token.getUnsignedAttributes() != null) {
            logger.info("unsigned attribute count: {}", token.getUnsignedAttributes().size());
        } else {
            logger.info("no unsigned attributes");
        }

        TimeStampTokenInfo tsti = token.getTimeStampInfo();
        logger.info("TSA: {}", tsti.getTsa());
        String oid = tsti.getPolicy().getId();
        logger.info("policy: {} ({})", oid, OidProperties.resolveOid(oid));
        logger.info("serial: {}", tsti.getSerialNumber());
        oid = tsti.getMessageImprintAlgOID().getId();
        logger.info("imprint algorithm: {} ({})", oid, OidProperties.resolveOid(oid));
        oid = tsti.getHashAlgorithm().getAlgorithm().getId();
        logger.info("hash algorithm: {} ({})", oid, OidProperties.resolveOid(oid));
        logger.info("time stamp: {}", tsti.getGenTime());

        GenTimeAccuracy gta = tsti.getGenTimeAccuracy();
        logger.info("accuracy: {} s, {} ms, {} us", gta.getSeconds(), gta.getMillis(), gta.getMicros());

        digest = tsti.getMessageImprintDigest();
    }

    private void validateCertificate() {
        if (certificate != null) {
            try {
                validate();
            } catch (RuntimeException re) {
                throw re;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            logger.info("timestamp not validated without certificate");
        }
    }

    private void verifySignerAttribute(ASN1Encodable signerAttribute) {
        ASN1TaggedObject object = (ASN1TaggedObject) signerAttribute;
        if (object.getTagNo() == 1) {
            try (final FileOutputStream outputStream = new FileOutputStream("/tmp/attr-cert.der")) {
                outputStream.write(object.toASN1Primitive().getEncoded());
                X509AttributeCertificateHolder attrHolder = new X509AttributeCertificateHolder(object.toASN1Primitive().getEncoded());
                logger.info("        attribute certificate from issuer {}", attrHolder.getIssuer().getNames()[0] + " saved to /tmp/attr-cert.der");
                for (org.bouncycastle.asn1.x509.Attribute attribute : attrHolder.getAttributes()) {
                    String attrOid = attribute.getAttrType().getId();
                    logger.info("            attribute: {} ({})", attrOid, OidProperties.resolveOid(attrOid));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            logger.info("        tagged object #{}", object.getTagNo());
        }
    }

    private void validate() throws OperatorException, CMSException {
        final SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate);
        try {
            token.validate(verifier);
            logger.info("timestamp successfully validated");
        } catch (Exception e) {
            logger.info("ERROR: validation failed");
            final SignerInformation signerInformation = token.toCMSSignedData().getSignerInfos().get(token.getSID());
            if (signerInformation.verify(verifier)) {
                logger.info("    CMS level successfully validated");
            } else {
                logger.info("    CMS level validation failed for: {} serial {}",
                        signerInformation.getSID().getIssuer(), signerInformation.getSID().getSerialNumber());
            }
        }
    }
}
