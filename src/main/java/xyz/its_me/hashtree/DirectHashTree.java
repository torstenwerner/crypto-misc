package xyz.its_me.hashtree;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

class DirectHashTree extends HashTree {
    TreeSet<UnsignedByteArray> data;

    public DirectHashTree() {
        data = new TreeSet<>();
    }

    @Override
    public void addDigest(byte[] digest) {
        UnsignedByteArray value = new UnsignedByteArray(digest);
        data.add(value);
    }

    @Override
    public void digestify() throws GeneralSecurityException {
        final MessageDigest md = getMessageDigest();
        for (UnsignedByteArray buffer : data) {
            md.update(buffer.getArray());
        }
        aggregatedDigest = md.digest();
    }

    @Override
    protected void updateDigestList(byte[] digest, List<List<byte[]>> list) {
        // add all document digests
        List<byte[]> firstElement = new ArrayList<byte[]>();
        for (UnsignedByteArray buffer : data) {
            firstElement.add(buffer.getArray());
        }
        list.add(firstElement);
    }
}
