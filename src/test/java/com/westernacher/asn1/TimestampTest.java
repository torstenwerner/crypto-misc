package com.westernacher.asn1;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.bouncycastle.cms.CMSSignedGenerator.DIGEST_SHA256;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.NONE;

@SpringBootTest(classes = TimestampTest.class, webEnvironment = NONE)
public class TimestampTest {

    @Value("classpath:/brak/BRAK_OCSP_CRL_Relay.cer")
    private Resource tsCertificate;

    @Value("classpath:/Nachricht44044226.zip")
    private Resource zipResource;

    private byte[] zipBytes;

    private SignerInformationVerifier verifier;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void beforeEach() throws CertificateException, OperatorCreationException, IOException {
        final X509Certificate certificate = (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(tsCertificate.getInputStream());
        zipBytes = IOUtils.toByteArray(zipResource.getInputStream());
        verifier = new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC")
                .build(certificate);
    }

    @Test
    public void shouldVerifyTimestamp(@Value("classpath:/Nachricht44044226.zip.p7s") Resource govResource)
            throws Exception {

        assertThat(govResource).isNotNull();

        final byte[] govBytes = IOUtils.toByteArray(govResource.getInputStream());
        final Optional<BeaTimestamp> beaTimestamp = BeaTimestamp.of(govBytes);

        assertThat(beaTimestamp)
                .get()
                .satisfies(beaTs -> {
                    assertThat(beaTs.getStatus()).isEqualTo(0);
                    assertThat(beaTs.getDetails()).isEqualTo("Operation Okay");

                    assertThat(beaTs.getHashAlgorithmId()).isEqualTo(DIGEST_SHA256);
                    assertThat(beaTs.getMessageImprintAlgOID()).isEqualTo(DIGEST_SHA256);
                    assertThat(beaTs.getMessageImprintHex()).isEqualTo("4da6bc1ca754a30828d8bf2ad66520fee2520d84b987fc4d39d64c47e5381f3b");
                    assertThat(beaTs.isMessageImprintValid(zipBytes)).isTrue();
                    assertThat(beaTs.getGenTime()).hasSameTimeAs("2020-09-12T09:41:25.000");

                    // Todo: fix validation
//                    assertThat(beaTs.isSignatureValid(verifier))
//                            .isTrue();
//                    assertThatCode(() -> beaTs.validate(verifier))
//                            .doesNotThrowAnyException();
                });
    }
}
