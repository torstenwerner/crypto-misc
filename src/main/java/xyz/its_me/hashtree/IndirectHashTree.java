package xyz.its_me.hashtree;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

class IndirectHashTree extends HashTree {
    private final static int MAX_INDIRECT_LEVEL = 5;

    private final TreeMap<Byte, HashTree> data;
    private final int level;

    public IndirectHashTree(int level) {
        data = new TreeMap<>();
        this.level = level;
    }

    public void addDigest(byte[] digest) {
        final byte key = digest[level];
        if (!data.containsKey(key)) {
            if (level < MAX_INDIRECT_LEVEL - 1) {
                data.put(key, new IndirectHashTree(level + 1));
            } else {
                data.put(key, new DirectHashTree());
            }
        }
        data.get(key).addDigest(digest);
    }

    @Override
    public void digestify() throws GeneralSecurityException {
        final TreeSet<UnsignedByteArray> aggregatedSet = new TreeSet<UnsignedByteArray>();
        for (Byte key : data.keySet()) {
            final HashTree hashTree = data.get(key);
            hashTree.digestify();
            aggregatedSet.add(new UnsignedByteArray(hashTree.aggregatedDigest));
        }
        final MessageDigest md = getMessageDigest();
        for (UnsignedByteArray element : aggregatedSet) {
            md.update(element.getArray());
        }
        aggregatedDigest = md.digest();
    }

    @Override
    protected void updateDigestList(byte[] digest, List<List<byte[]>> list) {
        // recurse into next subtree
        final byte firstKey = digest[level];
        data.get(firstKey).updateDigestList(digest, list);

        // add aggregated digests of all subtrees
        final List<byte[]> newElement = new ArrayList<byte[]>();
        for (Byte secondKey : data.keySet()) {
            if (firstKey != secondKey) {
                newElement.add(data.get(secondKey).aggregatedDigest);
            }
        }
        list.add(newElement);
    }
}
