package xyz.its_me.asn1;

import org.bouncycastle.cms.SignerInformationVerifier;
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

    private byte[] zipBytes;

    private byte[] signatureBytes;

    public BeaTimestampVerifier(byte[] zipBytes, byte[] signatureBytes) {
        this.zipBytes = zipBytes;
        this.signatureBytes = signatureBytes;
    }

    public static void verify(String zipFilename, String signatureFilename) {
        final File zipFile = new File(zipFilename);
        if (!zipFile.canRead()) {
            System.err.printf("Die ZIP-Datei %s kann nicht gelesen werden.%n", zipFilename);
            return;
        }

        final File signatureFile = new File(signatureFilename);
        if (!signatureFile.canRead()) {
            System.err.printf("Die Signatur-Datei %s kann nicht gelesen werden.%n", signatureFilename);
            return;
        }

        try {
            final FileInputStream zipStream = new FileInputStream(zipFile);
            final FileInputStream signatureStream = new FileInputStream(signatureFile);
            final BeaTimestampVerifier verifier = new BeaTimestampVerifier(zipStream.readAllBytes(), signatureStream.readAllBytes());
            verifier.execute();
        } catch (IOException e) {
            System.err.printf("Fehler beim Einlesen der Dateien: %s%n", e.getMessage());
        }
    }

    private void execute() {
        final Optional<BeaTimestamp> beaTimestamp = BeaTimestamp.of(signatureBytes);
        if (beaTimestamp.isEmpty()) {
            System.err.printf("Die Signatur-Datei konnte nicht verarbeitet werden.%n");
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
        System.out.printf("Status des proprietären Wrappers: %d – %s%n", beaTimestamp.getStatus(), beaTimestamp.getDetails());
        System.out.printf("%nDie nachfolgenden Daten stammen aus der PKCS7-Zeitstempelsignatur.%n%n");
        System.out.printf("Ist die Signatur gültig: %s%n", beaTimestamp.isSignatureValid(verifier) ? "ja" : "nein");
        System.out.printf("Ist der Zeitstempel gültig: %s%n", beaTimestamp.isValid(verifier) ? "ja" : "nein");
        System.out.printf("Wird die angegebene ZIP-Datei signiert: %s%n", beaTimestamp.isMessageImprintValid(zipBytes) ? "ja" : "nein");
        final DateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
        System.out.printf("Signaturzeitpunkt: %s%n", dateFormat.format(beaTimestamp.getGenTime()));
        System.out.printf("Genauigkeit des Zeitstempels: %ss%n", beaTimestamp.getGenTimeAccuracy().toString());
        System.out.printf("Policy-Id des Zeitstempeldienstes: %s (%s)%n", beaTimestamp.getPolicyId(), resolveOid(beaTimestamp.getPolicyId()));
        System.out.printf("Algorithmus des Hashes der ZIP-Datei: %s (%s)%n", beaTimestamp.getHashAlgorithmId(), resolveOid(beaTimestamp.getHashAlgorithmId()));
        System.out.printf("Hexadezimaler Hashwert der ZIP-Datei: %s%n", beaTimestamp.getMessageImprintHex());
    }
}
