package com.westernacher.asn1;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
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
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
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
        final Optional<BeaTimestamp> beaTimestamp = BeaTimestamp.of(govBytes);

        assertThat(beaTimestamp)
                .isPresent()
                .get()
                .satisfies(beaTs -> {
                    assertThat(beaTs.getStatus()).isEqualTo(0);
                    assertThat(beaTs.getDetails()).isEqualTo("Operation Okay");
                    assertThatCode(() -> assertPkcs7(beaTs.getPkcs7()))
                            .doesNotThrowAnyException();
                });
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

        // Todo: fix validation
//        assertThat(timeStampToken.isSignatureValid(verifier)).isTrue();

//        timeStampToken.validate(verifier);
    }

    private byte[] zipHash() throws Exception {
        final byte[] zipBytes = IOUtils.toByteArray(zipResource.getInputStream());
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(zipBytes);
    }
}
