package com.westernacher.hashtree;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;

import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.NONE;

@SpringBootTest(classes = TimestampTest.class, webEnvironment = NONE)
public class TimestampTest {

    @Value("classpath:/brak/BRAK_OCSP_CRL_Relay.cer")
    private Resource tsCertificate;

    @Value("classpath:/Nachricht44044226.zip")
    private Resource zipResource;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void shouldVerifyTimestamp(@Value("classpath:/Nachricht44044226.zip.p7s") Resource govResource)
            throws Exception {

        assertThat(govResource).isNotNull();

        final byte[] govBytes = IOUtils.toByteArray(govResource.getInputStream());
        final ASN1Sequence govSequence = ASN1Sequence.getInstance(govBytes);

        assertThat(govSequence.size()).isEqualTo(2);
        assertGovStatus(govSequence.getObjectAt(0));
        assertPkcs7(govSequence.getObjectAt(1));
    }

    private void assertGovStatus(ASN1Encodable govStatus) {
        assertThat(govStatus).isInstanceOf(ASN1Sequence.class);

        final ASN1Sequence govStatusSequence = (ASN1Sequence) govStatus;

        assertThat(govStatusSequence.size()).isEqualTo(2);

        final ASN1Encodable govStatusInteger = govStatusSequence.getObjectAt(0);

        assertThat(govStatusInteger).isInstanceOf(ASN1Integer.class);

        final int govStatusIntValue = ((ASN1Integer) govStatusInteger).intValueExact();

        assertThat(govStatusIntValue).isEqualTo(0);

        final ASN1Encodable govStatusStringSequence = govStatusSequence.getObjectAt(1);

        assertThat(govStatusStringSequence).isInstanceOf(ASN1Sequence.class);

        final ASN1Sequence govStatusStringSequenceCasted = (ASN1Sequence) govStatusStringSequence;

        assertThat(govStatusStringSequenceCasted.size()).isEqualTo(1);

        final ASN1Encodable govStatusString = govStatusStringSequenceCasted.getObjectAt(0);

        assertThat(govStatusString).isInstanceOf(ASN1String.class);

        assertThat(((ASN1String) govStatusString).getString()).isEqualTo("Operation Okay");
    }

    private void assertPkcs7(ASN1Encodable pkcs7) throws Exception {

        final CMSSignedData signedData = new CMSSignedData(pkcs7.toASN1Primitive().getEncoded());
        final TimeStampToken timeStampToken = new TimeStampToken(signedData);
        final TimeStampTokenInfo timeStampInfo = timeStampToken.getTimeStampInfo();

        // NIST SHA-256
        assertThat(timeStampInfo.getHashAlgorithm().getAlgorithm().getId()).isEqualTo("2.16.840.1.101.3.4.2.1");
        assertThat(timeStampInfo.getMessageImprintAlgOID().getId()).isEqualTo("2.16.840.1.101.3.4.2.1");
        assertThat(timeStampInfo.getMessageImprintDigest()).hasSize(32);
        assertThat(timeStampInfo.getMessageImprintDigest()).isEqualTo(zipHash());

        final X509Certificate certificate = (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(tsCertificate.getInputStream());
        final SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC")
                .build(certificate);

//        assertThat(timeStampToken.isSignatureValid(verifier)).isTrue();

//        timeStampToken.validate(verifier);
    }

    private byte[] zipHash() throws Exception {
        final byte[] zipBytes = IOUtils.toByteArray(zipResource.getInputStream());
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(zipBytes);
    }
}
