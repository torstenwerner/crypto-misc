package xyz.its_me.asn1;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;

public class Asn1Parser {

    private static final Logger logger = LoggerFactory.getLogger(Asn1Parser.class);

    private final StringBuilder output = new StringBuilder();

    private void addMessage(String message) {
        final String indentation = StringUtils.repeat(" ", indent * 4);
        output.append(indentation)
                .append(message)
                .append("\n");
    }

    private void mergeMessagesTo(Asn1Parser targetParser) {
        targetParser.output.append(output);
    }

    public void print() {
        logger.info("{}", output);
    }

    private void parse() {
        if (primitive == null) {
            logger.info("Cannot parse null!");
            System.exit(1);
        } else if (primitive instanceof ASN1Sequence sequence) {
            addMessage("sequence, length = " + sequence.size());
            sequence.forEach(asn1Encodable ->
                    new Asn1Parser(asn1Encodable.toASN1Primitive(), indent + 1).mergeMessagesTo(this));
        } else if (primitive instanceof ASN1Set set) {
            addMessage("set, length = " + set.size());
            set.forEach(asn1Encodable ->
                    new Asn1Parser(asn1Encodable.toASN1Primitive(), indent + 1).mergeMessagesTo(this));
        } else if (primitive instanceof ASN1Integer asn1Integer) {
            addMessage("integer = " + asn1Integer.getValue());
        } else if (primitive instanceof ASN1Enumerated enumerated) {
            addMessage("enumerated = " + enumerated.getValue());
        } else if (primitive instanceof ASN1ObjectIdentifier identifier) {
            final String oid = identifier.getId();
            addMessage("OID, id = " + oid + " (" + OidProperties.resolveOid(oid) + ")");
        } else if (primitive instanceof ASN1TaggedObject taggedObject) {
            addMessage("tagged object, #" + taggedObject.getTagNo());
            new Asn1Parser(taggedObject.toASN1Primitive(), indent + 1).mergeMessagesTo(this);
        } else if (primitive instanceof DERNull) {
            addMessage("null");
        } else if (primitive instanceof ASN1UTCTime utcTime) {
            addMessage("UTC time = " + utcTime.getTime());
        } else if (primitive instanceof ASN1GeneralizedTime generalizedTime) {
            addMessage("generalized time = " + generalizedTime.getTime());
        } else if (primitive instanceof ASN1Boolean asn1Boolean) {
            addMessage("boolean = " + asn1Boolean.isTrue());
        } else if (primitive instanceof DERIA5String ia5String) {
            addMessage("IA5String (" + ia5String.getString() + ")");
        } else if (primitive instanceof DERBMPString bmpString) {
            addMessage("BMPString (" + bmpString.getString() + ")");
        } else if (primitive instanceof DERPrintableString printableString) {
            addMessage("printable string (" + printableString.getString() + ")");
        } else if (primitive instanceof DERUTF8String printableString) {
            addMessage("UTF-8 string (" + printableString.getString() + ")");
        } else if (primitive instanceof DERBitString bitString) {
            final byte[] bytes = bitString.getBytes();
            String message = "bit string, " + bytes.length + " bytes";
            if (bytes.length <= 4) {
                message += ", as integer = " + bitString.intValue();
            }
            addMessage(message);
            new Asn1Parser(bytes, indent + 1).mergeMessagesTo(this);
        } else if (primitive instanceof ASN1OctetString octetString) {
            final byte[] bytes = octetString.getOctets();
            addMessage("octet string, " + bytes.length + " bytes, content = " + StringUtils.abbreviate(octetString.toString(), 64));
            new Asn1Parser(bytes, indent + 1).mergeMessagesTo(this);
        } else {
            addMessage("unknown object, class = " + primitive.getClass());
        }
    }

    private ASN1Primitive primitive;
    private final int indent;

    public Asn1Parser(ASN1Primitive primitive, int indent) {
        this.primitive = primitive;
        this.indent = indent;
        parse();
    }

    public Asn1Parser(byte[] bytes, int indent) {
        this.indent = indent;
        try {
            final String decodedString = Charset.availableCharsets().get("US-ASCII").newDecoder().
                    decode(ByteBuffer.wrap(bytes)).toString();
            if (!decodedString.matches(".*\\p{Cntrl}.*")) {
                addMessage("found printable ASCII string (" + decodedString + ")");
                return;
            }
        } catch (CharacterCodingException ignored) {
        }
        try {
            primitive = ASN1Primitive.fromByteArray(bytes);
            if (primitive.getEncoded().length != bytes.length) {
                addMessage("found neither printable ASCII string nor ASN.1 data");
            } else {
                addMessage("found ASN.1 data");
                parse();
            }
        } catch (IOException e) {
            addMessage("found neither printable ASCII string nor ASN.1 data: " + e.getMessage());
        }
    }

    public static void parse(String filename) throws IOException {
        if (!new File(filename).canRead()) {
            logger.error("Cannot read file {}.", filename);
            return;
        }

        ASN1Primitive object;
        try (var inputStream = new FileInputStream(filename)) {
            ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream);
            object = asn1InputStream.readObject();
        } catch (IOException e) {
            // try PEM as a fallback
            logger.info("Failed to read DER file - try to fallback to PEM format.");
            try (PemReader pemReader = new PemReader(new FileReader(filename))) {
                final byte[] pemContent = pemReader.readPemObject().getContent();
                try (ASN1InputStream asn1InputStream = new ASN1InputStream(pemContent)) {
                    object = asn1InputStream.readObject();
                }
            }
        }
        new Asn1Parser(object, 0).print();
        logger.info("size of encoded object: {}", object.getEncoded().length);
    }
}
