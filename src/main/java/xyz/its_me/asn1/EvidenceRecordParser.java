package xyz.its_me.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TimeStampToken;
import xyz.its_me.hashtree.HashTreeVerifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class EvidenceRecordParser {
    private final ASN1Encodable evidenceRecord;
    List<List<byte[]>> hashtree;
    TimeStampToken timestamptoken;

    public List<List<byte[]>> getHashtree() {
        return hashtree;
    }

    public TimeStampToken getTimestamptoken() {
        return timestamptoken;
    }

    public EvidenceRecordParser(ASN1Encodable evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    public void parse() {
        parseEvidenceRecord((ASN1Sequence) evidenceRecord);
    }

    private void parseEvidenceRecord(ASN1Sequence evidenceRecord) {
        parseVersion((ASN1Integer) evidenceRecord.getObjectAt(0));
        parseDigestAlgorithms((ASN1Sequence) evidenceRecord.getObjectAt(1));
        int currentIndex = 2;
        if (isTaggedObject(evidenceRecord.getObjectAt(currentIndex), 0)) {
            System.out.println("with CryptoInfos");
            currentIndex++;
        } else {
            System.out.println("without CryptoInfos");
        }
        if (isTaggedObject(evidenceRecord.getObjectAt(currentIndex), 1)) {
            System.out.println("with EncryptionInfo");
            currentIndex++;
        } else {
            System.out.println("without EncryptionInfo");
        }
        parseArchiveTimestampSequence((ASN1Sequence) evidenceRecord.getObjectAt(currentIndex));
    }

    private void parseVersion(ASN1Integer version) {
        System.out.println("version (should be 1): " + version.getValue());
    }

    private void parseDigestAlgorithms(ASN1Sequence digestAlgorithms) {
        System.out.println("digestAlgorithms:");
        for (int i = 0; i < digestAlgorithms.size(); i++) {
            parseAlgorithmIdentifier((ASN1Sequence) digestAlgorithms.getObjectAt(i));
        }
    }

    private void parseAlgorithmIdentifier(ASN1Sequence algorithmIdentifier) {
        parseAlgorithmIdentifier(algorithmIdentifier, "");
    }

    private void parseAlgorithmIdentifier(ASN1Sequence algorithmIdentifier, String indent) {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) algorithmIdentifier.getObjectAt(0);
        System.out.println(indent + "  oid: " + oid.getId() + " (" + OidProperties.resolveOid(oid.getId()) + ")");
        if (algorithmIdentifier.size() == 2) {
            System.out.println(indent + "    with parameters of type " + algorithmIdentifier.getObjectAt(1).getClass().getName());
        } else {
            System.out.println(indent + "    without parameters");
        }
    }

    private void parseArchiveTimestampSequence(ASN1Sequence archiveTimestampSequence) {
        System.out.println("archiveTimestampChains:");
        for (int i = 0; i < archiveTimestampSequence.size(); i++) {
            parseArchiveTimestampChain((ASN1Sequence) archiveTimestampSequence.getObjectAt(i));
        }
    }

    private void parseArchiveTimestampChain(ASN1Sequence archiveTimestampChain) {
        System.out.println("  archiveTimestamp:");
        for (int i = 0; i < archiveTimestampChain.size(); i++) {
            parseArchiveTimestamp((ASN1Sequence) archiveTimestampChain.getObjectAt(i));
        }
    }

    private void parseArchiveTimestamp(ASN1Sequence archiveTimestamp) {
        int index = 0;
        if (isTaggedObject(archiveTimestamp.getObjectAt(index), 0)) {
            final ASN1TaggedObject taggedObject = (ASN1TaggedObject) archiveTimestamp.getObjectAt(index);
            parseAlgorithmIdentifier(ASN1Sequence.getInstance(taggedObject), "  ");
            index++;
        } else {
            System.out.println("    without algorithmIdentifier");
        }
        if (isTaggedObject(archiveTimestamp.getObjectAt(index), 1)) {
            System.out.println("    with attributes");
            index++;
        } else {
            System.out.println("    without attributes");
        }
        if (isTaggedObject(archiveTimestamp.getObjectAt(index), 2)) {
            final ASN1TaggedObject taggedObject = (ASN1TaggedObject) archiveTimestamp.getObjectAt(index);
            parseReducedHashtree(ASN1Sequence.getInstance(taggedObject));
            index++;
        } else {
            System.out.println("    without reducedHashtree");
        }
        final ContentInfo contentInfo = ContentInfo.getInstance(archiveTimestamp.getObjectAt(index));
        try {
            timestamptoken = new TimeStampToken(contentInfo);
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void parseReducedHashtree(ASN1Sequence reducedHashtree) {
        System.out.println("    size of reducedHashtree: " + reducedHashtree.size());
        hashtree = new ArrayList<>();
        for (int i = 0; i < reducedHashtree.size(); i++) {
            ASN1Sequence partialHashtree = (ASN1Sequence) reducedHashtree.getObjectAt(i);
            System.out.println("      size of partialHashtree: " + partialHashtree.size());
            List<byte[]> partialList = new ArrayList<>();
            for (int j = 0; j < partialHashtree.size(); j++) {
                ASN1OctetString octetString = (ASN1OctetString) partialHashtree.getObjectAt(j);
                partialList.add(octetString.getOctets());
            }
            hashtree.add(partialList);
        }
    }

    private boolean isTaggedObject(ASN1Encodable object, int tagNumber) {
        if (object instanceof ASN1TaggedObject) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) object;
            return taggedObject.getTagNo() == tagNumber;
        } else {
            return false;
        }
    }

    // e.g. sample/test02.txt-er.der sample/tss-signtrust-50.cer sample/test02.txt
    public static void parse(
            String erName, String certName, String dataName) throws IOException, GeneralSecurityException {
        if (!new File(erName).canRead()) {
            System.err.printf("Cannot read file %s.%n", erName);
            return;
        }
        if (!new File(certName).canRead()) {
            System.err.printf("Cannot read file %s.%n", certName);
            return;
        }
        if (!new File(dataName).canRead()) {
            System.err.printf("Cannot read file %s.%n", dataName);
            return;
        }

        EvidenceRecordParser parser;
        try (ASN1InputStream inputStream = new ASN1InputStream(new FileInputStream(erName))) {
            parser = new EvidenceRecordParser(inputStream.readObject());
        } catch (IOException e) {
            System.err.printf("error parsing evidence record %s: %s%n", erName, e.getMessage());
            return;
        }
        parser.parse();
        System.out.println("evidence record successfully parsed");

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        try {
            certificate = (X509Certificate) factory.generateCertificate(new FileInputStream(certName));
        } catch (CertificateException e) {
            System.err.printf("error reading certificate %s: %s%n", certName, e.getMessage());
            return;
        }
        VerifyTST timestampVerifier = new VerifyTST(parser.getTimestamptoken(), certificate);
        timestampVerifier.verify();
        System.out.println("timestamp successfully verified");

        HashTreeVerifier hashTreeVerifier = new HashTreeVerifier(timestampVerifier.getDigest());
        MessageDigest md = MessageDigest.getInstance("SHA-256"); // FIXME: algorithm should be calculated from timestamptoken
        final byte[] document;
        try (var inputStream = new FileInputStream(dataName)) {
            document = inputStream.readAllBytes();
        }
        hashTreeVerifier.verify(parser.getHashtree(), md.digest(document));

        System.out.println("evidence record successfully verified");
    }
}
