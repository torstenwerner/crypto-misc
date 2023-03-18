package xyz.its_me.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(EvidenceRecordParser.class);
    public static final String CANNOT_READ_FILE = "Cannot read file {}.";

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
            logger.info("with CryptoInfos");
            currentIndex++;
        } else {
            logger.info("without CryptoInfos");
        }
        if (isTaggedObject(evidenceRecord.getObjectAt(currentIndex), 1)) {
            logger.info("with EncryptionInfo");
            currentIndex++;
        } else {
            logger.info("without EncryptionInfo");
        }
        parseArchiveTimestampSequence((ASN1Sequence) evidenceRecord.getObjectAt(currentIndex));
    }

    private void parseVersion(ASN1Integer version) {
        logger.info("version (should be 1): {}", version.getValue());
    }

    private void parseDigestAlgorithms(ASN1Sequence digestAlgorithms) {
        logger.info("digestAlgorithms:");
        for (int i = 0; i < digestAlgorithms.size(); i++) {
            parseAlgorithmIdentifier((ASN1Sequence) digestAlgorithms.getObjectAt(i));
        }
    }

    private void parseAlgorithmIdentifier(ASN1Sequence algorithmIdentifier) {
        parseAlgorithmIdentifier(algorithmIdentifier, "");
    }

    private void parseAlgorithmIdentifier(ASN1Sequence algorithmIdentifier, String indent) {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) algorithmIdentifier.getObjectAt(0);
        if (logger.isInfoEnabled()) {
            logger.info("{}  oid: {} ({})", indent, oid.getId(), OidProperties.resolveOid(oid.getId()));
        }
        if (algorithmIdentifier.size() == 2) {
            logger.info("{}    with parameters of type {}", indent, algorithmIdentifier.getObjectAt(1).getClass().getName());
        } else {
            logger.info("{}    without parameters", indent);
        }
    }

    private void parseArchiveTimestampSequence(ASN1Sequence archiveTimestampSequence) {
        logger.info("archiveTimestampChains:");
        for (int i = 0; i < archiveTimestampSequence.size(); i++) {
            parseArchiveTimestampChain((ASN1Sequence) archiveTimestampSequence.getObjectAt(i));
        }
    }

    private void parseArchiveTimestampChain(ASN1Sequence archiveTimestampChain) {
        logger.info("  archiveTimestamp:");
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
            logger.info("    without algorithmIdentifier");
        }
        if (isTaggedObject(archiveTimestamp.getObjectAt(index), 1)) {
            logger.info("    with attributes");
            index++;
        } else {
            logger.info("    without attributes");
        }
        if (isTaggedObject(archiveTimestamp.getObjectAt(index), 2)) {
            final ASN1TaggedObject taggedObject = (ASN1TaggedObject) archiveTimestamp.getObjectAt(index);
            parseReducedHashtree(ASN1Sequence.getInstance(taggedObject));
            index++;
        } else {
            logger.info("    without reducedHashtree");
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
        logger.info("    size of reducedHashtree: {}", reducedHashtree.size());
        hashtree = new ArrayList<>();
        for (int i = 0; i < reducedHashtree.size(); i++) {
            ASN1Sequence partialHashtree = (ASN1Sequence) reducedHashtree.getObjectAt(i);
            logger.info("      size of partialHashtree: {}", partialHashtree.size());
            List<byte[]> partialList = new ArrayList<>();
            for (int j = 0; j < partialHashtree.size(); j++) {
                ASN1OctetString octetString = (ASN1OctetString) partialHashtree.getObjectAt(j);
                partialList.add(octetString.getOctets());
            }
            hashtree.add(partialList);
        }
    }

    private boolean isTaggedObject(ASN1Encodable object, int tagNumber) {
        if (object instanceof ASN1TaggedObject taggedObject) {
            return taggedObject.getTagNo() == tagNumber;
        } else {
            return false;
        }
    }

    // e.g. sample/test02.txt-er.der sample/tss-signtrust-50.cer sample/test02.txt
    public static void parse(
            String erName, String certName, String dataName) throws IOException, GeneralSecurityException {
        if (!new File(erName).canRead()) {
            logger.error(CANNOT_READ_FILE, erName);
            return;
        }
        if (!new File(certName).canRead()) {
            logger.error(CANNOT_READ_FILE, certName);
            return;
        }
        if (!new File(dataName).canRead()) {
            logger.error(CANNOT_READ_FILE, dataName);
            return;
        }

        EvidenceRecordParser parser;
        try (ASN1InputStream inputStream = new ASN1InputStream(new FileInputStream(erName))) {
            parser = new EvidenceRecordParser(inputStream.readObject());
        } catch (IOException e) {
            final var message = "error parsing evidence record %s".formatted(erName);
            logger.error(message, e);
            return;
        }
        parser.parse();
        logger.info("evidence record successfully parsed");

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        try {
            certificate = (X509Certificate) factory.generateCertificate(new FileInputStream(certName));
        } catch (CertificateException e) {
            final var message = "error reading certificate %s".formatted(certName);
            logger.error(message, e);
            return;
        }
        VerifyTST timestampVerifier = new VerifyTST(parser.getTimestamptoken(), certificate);
        timestampVerifier.verify();
        logger.info("timestamp successfully verified");

        HashTreeVerifier hashTreeVerifier = new HashTreeVerifier(timestampVerifier.getDigest());
        MessageDigest md = MessageDigest.getInstance("SHA-256"); // FIXME: algorithm should be calculated from timestamptoken
        final byte[] document;
        try (var inputStream = new FileInputStream(dataName)) {
            document = inputStream.readAllBytes();
        }
        hashTreeVerifier.verify(parser.getHashtree(), md.digest(document));

        logger.info("evidence record successfully verified");
    }
}
