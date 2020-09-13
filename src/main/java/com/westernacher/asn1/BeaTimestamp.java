package com.westernacher.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;

import java.util.Optional;

import static java.lang.String.format;

/**
 * A non standard timestamp signoture format that embeds a standard pkcs7 timestamp signature.
 */
public class BeaTimestamp {

    private final int status;

    private final String details;

    private final ASN1Sequence pkcs7;

    /**
     * @throws IllegalArgumentException if the argument cannot be converted
     * @throws ArithmeticException if the status is not in int range
     */
    private BeaTimestamp(byte[] bytes) {
        final ASN1Sequence inputSequence = ASN1Sequence.getInstance(bytes);
        if (inputSequence.size() != 2) {
            final String message = format("Expected a sequence of 2 items but got %d item(s).", inputSequence.size());
            throw new IllegalArgumentException(message);
        }

        final ASN1Encodable wrapperSequence = inputSequence.getObjectAt(0);
        if (!(wrapperSequence instanceof ASN1Sequence)) {
            final String message = format("Expected type ASN1Sequence but got %s.", wrapperSequence.getClass().getName());
            throw new IllegalArgumentException(message);
        }
        final ASN1Sequence wrapperSequenceCasted = (ASN1Sequence) wrapperSequence;
        if (wrapperSequenceCasted.size() != 2) {
            final String message = format("Expected a sequence of 2 items but got %d item(s).", wrapperSequenceCasted.size());
            throw new IllegalArgumentException(message);
        }

        final ASN1Encodable intItem = wrapperSequenceCasted.getObjectAt(0);
        if (!(intItem instanceof ASN1Integer)) {
            final String message = format("Expected type ASN1Integer but got %s.", intItem.getClass().getName());
            throw new IllegalArgumentException(message);
        }
        status = ((ASN1Integer) intItem).intValueExact();

        final ASN1Encodable stringSequence = wrapperSequenceCasted.getObjectAt(1);
        if (!(stringSequence instanceof ASN1Sequence)) {
            final String message = format("Expected type ASN1Sequence but got %s.", stringSequence.getClass().getName());
            throw new IllegalArgumentException(message);
        }

        final ASN1Sequence stringSequenceCasted = (ASN1Sequence) stringSequence;
        if (stringSequenceCasted.size() != 1) {
            final String message = format("Expected a sequence of 1 item but got %d item(s).", stringSequenceCasted.size());
            throw new IllegalArgumentException(message);
        }

        final ASN1Encodable detailString = stringSequenceCasted.getObjectAt(0);
        if (!(detailString instanceof ASN1String)) {
            final String message = format("Expected type ASN1String but got %s.", detailString.getClass().getName());
            throw new IllegalArgumentException(message);
        }

        details = ((ASN1String) detailString).getString();

        final ASN1Encodable pkcs7Item = inputSequence.getObjectAt(1);
        if (!(pkcs7Item instanceof ASN1Sequence)) {
            final String message = format("Expected type ASN1Sequence but got %s.", pkcs7Item.getClass().getName());
            throw new IllegalArgumentException(message);
        }
        pkcs7 = (ASN1Sequence) pkcs7Item;
    }

    /**
     * Creates a {@link BeaTimestamp} from a byte array.
     */
    public static Optional<BeaTimestamp> of(byte[] bytes) {
        try {
            return Optional.of(new BeaTimestamp(bytes));
        } catch (RuntimeException e) {
            System.err.printf("Failed to parse BeaTimestamp: %s%n", e.getMessage());
            e.printStackTrace(System.err);
            return Optional.empty();
        }
    }

    /**
     * Returns the status int.
     */
    public int getStatus() {
        return status;
    }

    /**
     * Returns the status details.
     */
    public String getDetails() {
        return details;
    }

    /**
     * Returns the embedded pkcs7 structure.
     */
    public ASN1Sequence getPkcs7() {
        return pkcs7;
    }
}
