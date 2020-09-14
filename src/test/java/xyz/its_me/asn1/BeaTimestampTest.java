package xyz.its_me.asn1;

import org.assertj.core.api.Assertions;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import xyz.its_me.Application;
import xyz.its_me.Utils;

import java.io.IOException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.bouncycastle.cms.CMSSignedGenerator.DIGEST_SHA256;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.NONE;

@SpringBootTest(classes = Application.class, webEnvironment = NONE)
public class BeaTimestampTest {

    @Value("classpath:/brak/BRAK_beA_Zeitstempel.cer")
    private Resource tsCertificate;

    @Value("classpath:/Nachricht44044226.zip")
    private Resource zipResource;

    private byte[] zipBytes;

    private SignerInformationVerifier verifier;

    @BeforeEach
    public void beforeEach() throws IOException {
        zipBytes = zipResource.getInputStream().readAllBytes();
        verifier = Utils.fromCertificate(tsCertificate.getInputStream());
    }

    @Test
    public void shouldVerifyTimestamp(@Value("classpath:/Nachricht44044226.zip.p7s") Resource govResource)
            throws Exception {

        assertThat(govResource).isNotNull();

        final byte[] govBytes = govResource.getInputStream().readAllBytes();
        final Optional<BeaTimestamp> beaTimestamp = BeaTimestamp.of(govBytes);

        Assertions.assertThat(beaTimestamp)
                .get()
                .satisfies(beaTs -> {
                    assertThat(beaTs.getStatus()).isEqualTo(0);
                    assertThat(beaTs.getDetails()).isEqualTo("Operation Okay");

                    assertThat(beaTs.getHashAlgorithmId()).isEqualTo(DIGEST_SHA256);
                    assertThat(beaTs.getMessageImprintAlgOID()).isEqualTo(DIGEST_SHA256);
                    assertThat(beaTs.getMessageImprintHex()).isEqualTo("4da6bc1ca754a30828d8bf2ad66520fee2520d84b987fc4d39d64c47e5381f3b");
                    assertThat(beaTs.isMessageImprintValid(zipBytes)).isTrue();
                    assertThat(beaTs.getGenTime())
                            .withDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")
                            .hasSameTimeAs("2020-09-12T07:41:25+00:00");
                    assertThat(beaTs.getGenTimeAccuracy().toString()).isEqualTo("5.000000");
                    assertThat(beaTs.getPolicyId()).isEqualTo("1.1.1");

                    assertThat(beaTs.isSignatureValid(verifier)).isTrue();
                    assertThat(beaTs.isValid(verifier)).isTrue();
                });
    }
}
