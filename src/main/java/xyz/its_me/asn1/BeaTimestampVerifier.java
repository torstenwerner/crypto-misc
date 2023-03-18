package xyz.its_me.asn1;

import org.bouncycastle.cms.SignerInformationVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import xyz.its_me.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Optional;

import static xyz.its_me.asn1.OidProperties.resolveOid;

/**
 * Verifies a beA timestamp. Messages are in german.
 */
public class BeaTimestampVerifier {

    private static final Logger logger = LoggerFactory.getLogger(BeaTimestampVerifier.class);

    private final byte[] zipBytes;

    private final byte[] signatureBytes;

    public BeaTimestampVerifier(byte[] zipBytes, byte[] signatureBytes) {
        this.zipBytes = zipBytes;
        this.signatureBytes = signatureBytes;
    }

    public static void verify(String zipFilename, String signatureFilename) {
        final File zipFile = new File(zipFilename);
        if (!zipFile.canRead()) {
            logger.error("Die ZIP-Datei %s kann nicht gelesen werden: {}", zipFilename);
            return;
        }

        final File signatureFile = new File(signatureFilename);
        if (!signatureFile.canRead()) {
            logger.error("Die Signatur-Datei {} kann nicht gelesen werden.", signatureFilename);
            return;
        }

        try (FileInputStream zipStream = new FileInputStream(zipFile);
             FileInputStream signatureStream = new FileInputStream(signatureFile)) {
            final BeaTimestampVerifier verifier = new BeaTimestampVerifier(zipStream.readAllBytes(), signatureStream.readAllBytes());
            verifier.execute();
        } catch (IOException e) {
            logger.error("Fehler beim Einlesen der Dateien.", e);
        }
    }

    private void execute() {
        final Optional<BeaTimestamp> beaTimestamp = BeaTimestamp.of(signatureBytes);
        if (beaTimestamp.isEmpty()) {
            logger.error("Die Signatur-Datei konnte nicht verarbeitet werden.");
            return;
        }

        final Resource certificate = new ClassPathResource("/brak/BRAK_beA_Zeitstempel.cer");
        final SignerInformationVerifier verifier;
        try {
            verifier = Utils.fromCertificate(certificate.getInputStream());
        } catch (IOException e) {
            throw new RuntimeException("Fehler beim Lesen des Zertifikates BRAK_beA_Zeitstempel.cer.");
        }

        display(beaTimestamp.get(), verifier);
    }

    private void display(BeaTimestamp beaTimestamp, SignerInformationVerifier verifier) {
        if (logger.isInfoEnabled()) {
            logger.info("Status des proprietären Wrappers: {} – {}", beaTimestamp.getStatus(), beaTimestamp.getDetails());
            logger.info("Die nachfolgenden Daten stammen aus der PKCS7-Zeitstempelsignatur.");
            logger.info("Ist die Signatur gültig: {}", beaTimestamp.isSignatureValid(verifier) ? "ja" : "nein");
            logger.info("Ist der Zeitstempel gültig: {}", beaTimestamp.isValid(verifier) ? "ja" : "nein");
            logger.info("Wird die angegebene ZIP-Datei signiert: {}", beaTimestamp.isMessageImprintValid(zipBytes) ? "ja" : "nein");
            final DateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
            logger.info("Signaturzeitpunkt: {}", dateFormat.format(beaTimestamp.getGenTime()));
            logger.info("Genauigkeit des Zeitstempels: {}s", beaTimestamp.getGenTimeAccuracy());
            logger.info("Policy-Id des Zeitstempeldienstes: {} ({})", beaTimestamp.getPolicyId(), resolveOid(beaTimestamp.getPolicyId()));
            logger.info("Algorithmus des Hashes der ZIP-Datei: {} ({})", beaTimestamp.getHashAlgorithmId(), resolveOid(beaTimestamp.getHashAlgorithmId()));
            logger.info("Hexadezimaler Hashwert der ZIP-Datei: {}", beaTimestamp.getMessageImprintHex());
            logger.info("Ergebnis der Zertifikatsprüfung: noch nicht implementiert.");
        }
    }
}
