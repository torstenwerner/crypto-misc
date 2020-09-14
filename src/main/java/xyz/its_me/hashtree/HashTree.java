package xyz.its_me.hashtree;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public abstract class HashTree {
    protected byte[] aggregatedDigest;

    /**
     * can be called after digestify()
     * @return aggregated / root Digest for the (sub) tree
     */
    public byte[] getAggregatedDigest() {
        return aggregatedDigest;
    }

    /**
     * adds a new digest to the tree, must be called before digestify()
     * @param digest
     */
    public abstract void addDigest(byte[] digest);

    /**
     * @return new instance of a HashTree
     */
    public static HashTree getInstance() {
        return new IndirectHashTree(0);
    }

    protected static MessageDigest getMessageDigest() throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256");
    }

    /**
     * calculates the aggregated digests
     * @throws GeneralSecurityException
     */
    public abstract void digestify() throws GeneralSecurityException;

    protected abstract void updateDigestList(byte[] digest, List<List<byte[]>> list);

    /**
     * must be called after digestify()
     * @return the reduced tree for digest
     */
    public List<List<byte[]>> getReducedTree(byte[] digest) {
        final List<List<byte[]>> list = new ArrayList<List<byte[]>>();
        updateDigestList(digest, list);
        return list;
    }
}
