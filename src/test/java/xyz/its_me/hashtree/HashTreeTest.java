package xyz.its_me.hashtree;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class HashTreeTest {

    private static byte[] getDigest(String data) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data.getBytes(UTF_8));
    }

    private HashTree hashTree;
    private byte[] data01, data02, data03, data04;
    private List<List<byte[]>> digestList01;
    private HashTreeVerifier verifier, wrongRootVerifier;

    @BeforeEach
    public void setup() throws GeneralSecurityException {
        hashTree = HashTree.getInstance();
        data01 = getDigest("Hello World");
        hashTree.addDigest(data01);
        data02 = getDigest("Hällo Wörld");
        hashTree.addDigest(data02);
        data03 = getDigest("hello Wörld");
        hashTree.addDigest(data03);
        data04 = getDigest("should fail");

        hashTree.digestify();
        digestList01 = hashTree.getReducedTree(data01);
        hashTree.getReducedTree(data02); // should not fail

        verifier = new HashTreeVerifier(hashTree.getAggregatedDigest());
        wrongRootVerifier = new HashTreeVerifier(data04);
    }

    @Test
    public void testHashtree() throws GeneralSecurityException {
        assertThat(digestList01).hasSize(6);
        int fullSize = 0;
        for (List<byte[]> subList : digestList01) {
            fullSize += subList.size();
        }
        assertThat(fullSize).isEqualTo(3);
        verifier.verify(digestList01, data01);
    }

    @Test
    public void testWrongTree() {
        assertThatThrownBy(() -> verifier.verify(digestList01, data02))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void testWrongDigest() {
        assertThatThrownBy(() -> hashTree.getReducedTree(data04))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void testModifiedTree() {
        digestList01.get(0).get(0)[0] += 1;
        assertThatThrownBy(() -> verifier.verify(digestList01, data01))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void testWrongRoot() {
        assertThatThrownBy(() -> wrongRootVerifier.verify(digestList01, data01))
                .isInstanceOf(RuntimeException.class);
    }
}
