package xyz.its_me.asn1;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;

import static java.lang.String.format;

public class Asn1Parser {
    private StringBuffer output = new StringBuffer();

    private void addMessage(String message) {
        final String indentation = StringUtils.repeat(" ", indent * 4);
        output.append(indentation + message + "\n");
    }

    private void mergeMessagesTo(Asn1Parser targetParser) {
        targetParser.output.append(output);
    }

    public void print() {
        System.out.print(output.toString());
    }

    private void parse() {
        if (primitive == null) {
            System.err.println("Cannot parse null!");
            System.exit(1);
        } else if (primitive instanceof ASN1Sequence) {
            ASN1Sequence sequence = (ASN1Sequence) primitive;
            addMessage("sequence, length = " + sequence.size());
            for (int i = 0; i < sequence.size(); i++) {
                new Asn1Parser(sequence.getObjectAt(i).toASN1Primitive(), indent + 1).mergeMessagesTo(this);
            }
        } else if (primitive instanceof ASN1Set) {
            ASN1Set set = (ASN1Set) primitive;
            addMessage("set, length = " + set.size());
            for (int i = 0; i < set.size(); i++) {
                new Asn1Parser((ASN1Primitive) set.getObjectAt(i), indent + 1).mergeMessagesTo(this);
            }
        } else if (primitive instanceof ASN1Integer) {
            ASN1Integer asn1Integer = (ASN1Integer) primitive;
            addMessage("integer = " + asn1Integer.getValue());
        } else if (primitive instanceof ASN1Enumerated) {
            ASN1Enumerated enumerated = (ASN1Enumerated) primitive;
            addMessage("enumerated = " + enumerated.getValue());
        } else if (primitive instanceof ASN1ObjectIdentifier) {
            ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) primitive;
            final String oid = identifier.getId();
            addMessage("OID, id = " + oid + " (" + OidProperties.resolveOid(oid) + ")");
        } else if (primitive instanceof ASN1TaggedObject) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) primitive;
            addMessage("tagged object, #" + taggedObject.getTagNo());
            new Asn1Parser(taggedObject.getObject(), indent + 1).mergeMessagesTo(this);
        } else if (primitive instanceof DERNull) {
            addMessage("null");
        } else if (primitive instanceof ASN1UTCTime) {
            ASN1UTCTime utcTime = (ASN1UTCTime) primitive;
            addMessage("UTC time = " + utcTime.getTime());
        } else if (primitive instanceof ASN1GeneralizedTime) {
            ASN1GeneralizedTime generalizedTime = (ASN1GeneralizedTime) primitive;
            addMessage("generalized time = " + generalizedTime.getTime());
        } else if (primitive instanceof ASN1Boolean) {
            ASN1Boolean asn1Boolean = (ASN1Boolean) primitive;
            addMessage("boolean = " + asn1Boolean.isTrue());
        } else if (primitive instanceof DERIA5String) {
            DERIA5String ia5String = (DERIA5String) primitive;
            addMessage("IA5String (" + ia5String.getString() + ")");
        } else if (primitive instanceof DERBMPString) {
            DERBMPString bmpString = (DERBMPString) primitive;
            addMessage("BMPString (" + bmpString.getString() + ")");
        } else if (primitive instanceof DERPrintableString) {
            DERPrintableString printableString = (DERPrintableString) primitive;
            addMessage("printable string (" + printableString.getString() + ")");
        } else if (primitive instanceof DERUTF8String) {
            DERUTF8String printableString = (DERUTF8String) primitive;
            addMessage("UTF-8 string (" + printableString.getString() + ")");
        } else if (primitive instanceof DERBitString) {
            DERBitString bitString = (DERBitString) primitive;
            final byte[] bytes = bitString.getBytes();
            String message = "bit string, " + bytes.length + " bytes";
            if (bytes.length <= 4) {
                message += ", as integer = " + bitString.intValue();
            }
            addMessage(message);
            new Asn1Parser(bytes, indent + 1).mergeMessagesTo(this);
        } else if (primitive instanceof ASN1OctetString) {
            ASN1OctetString octetString = (ASN1OctetString) primitive;
            final byte[] bytes = octetString.getOctets();
            addMessage("octet string, " + bytes.length + " bytes, content = " + StringUtils.abbreviate(octetString.toString(), 64));
            new Asn1Parser(bytes, indent + 1).mergeMessagesTo(this);
        } else if (primitive instanceof DERApplicationSpecific) {
            DERApplicationSpecific specific = (DERApplicationSpecific) primitive;
            final byte[] bytes = specific.getContents();
            addMessage("application specific data, tag = " + specific.getApplicationTag() + ", " + bytes.length + " bytes");
            new Asn1Parser(bytes, indent + 1).mergeMessagesTo(this);
        } else {
            addMessage("unknown object, class = " + primitive.getClass());
        }
    }

    private ASN1Primitive primitive;
    private int indent;

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
        } catch (CharacterCodingException e) {
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
            System.err.println(format("Cannot read file %s.", filename));
            return;
        }

        ASN1Primitive object;
        try {
            ASN1InputStream asn1InputStream = new ASN1InputStream(new FileInputStream(filename));
            object = asn1InputStream.readObject();
        } catch (IOException e) {
            // try PEM as a fallback
            System.out.println("Failed to read DER file - try to fallback to PEM format.");
            final PemReader pemReader = new PemReader(new FileReader(filename));
            final byte[] pemContent = pemReader.readPemObject().getContent();
            ASN1InputStream asn1InputStream = new ASN1InputStream(pemContent);
            object = asn1InputStream.readObject();
        }
        new Asn1Parser(object, 0).print();
        System.out.println("size of encoded object: " + object.getEncoded().length);
    }
}
