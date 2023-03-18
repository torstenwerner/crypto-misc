package xyz.its_me.hashtree;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;

public class HashTreeVerifier {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final int SHA256_SIZE = 32;

    private final byte[] treeDigest;

    private static void checkDigest(byte[] digest) {
        if (digest == null || digest.length != SHA256_SIZE) {
            throw new RuntimeException("invalid digest");
        }
    }

    private void checkTree(List<List<byte[]>> tree) {
        final int treeSize = tree.size();
        if (treeSize == 0) {
            throw new RuntimeException("empty tree");
        }
        for (List<byte[]> subList : tree) {
            for (byte[] digest : subList) {
                checkDigest(digest);
            }
        }
    }

    private static void checkDigestInList(List<byte[]> list, byte[] digest) {
        for (byte[] element : list) {
            if (Arrays.equals(element, digest)) {
                return;
            }
        }
        throw new RuntimeException("digest missing in tree");
    }

    /**
     * @param treeDigest the expected tree's root digest
     */
    public HashTreeVerifier(byte[] treeDigest) {
        checkDigest(treeDigest);
        this.treeDigest = treeDigest;
    }

    private void debug(String message, byte[] value) {
        logger.debug("{}: {}", message, value);
    }

    /**
     * verifies that digest and reduced tree match the tree's root digest
     */
    public void verify(List<List<byte[]>> reducedTree, byte[] digest) {
        debug("doc digest", digest);

        checkTree(reducedTree);
        checkDigest(digest);

        final int treeSize = reducedTree.size();
        checkDigestInList(reducedTree.get(0), digest);

        byte[] calculatedDigest = getDigest(reducedTree.get(0), null);
        debug("first calculated digest", calculatedDigest);

        for (int i = 1; i < treeSize; i++) {
            calculatedDigest = getDigest(reducedTree.get(i), calculatedDigest);
            debug("next calculated digest", calculatedDigest);
        }

        debug("tree/timestamp digest", treeDigest);
        if (!Arrays.equals(calculatedDigest, treeDigest)) {
            throw new RuntimeException("tree digest does not match");
        }
    }

    private byte[] getDigest(List<byte[]> partialTree, byte[] extraElement) {
        TreeSet<UnsignedByteArray> sortedSet = new TreeSet<>();
        if (extraElement != null) {
            sortedSet.add(new UnsignedByteArray(extraElement));
        }
        for (byte[] element : partialTree) {
            sortedSet.add(new UnsignedByteArray(element));
        }
        MessageDigest md = createMessageDigest();
        for (UnsignedByteArray element : sortedSet) {
            debug("  element", element.getArray());
            md.update(element.getArray());
        }
        return md.digest();
    }

    private MessageDigest createMessageDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
