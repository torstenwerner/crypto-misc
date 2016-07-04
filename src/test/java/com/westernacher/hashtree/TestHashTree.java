package com.westernacher.hashtree;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class TestHashTree {
	private static byte[] getDigest(String data) throws GeneralSecurityException, IOException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(data.getBytes("UTF-8"));
	}
	
	private HashTree hashTree;
	private byte[] data01, data02, data03, data04;
	private List<List<byte[]>> digestList01;
	private HashTreeVerifier verifier, wrongRootVerifier;
	
	@Before
	public void setup() throws GeneralSecurityException, IOException {
		hashTree = HashTree.getInstance();
		data01 = getDigest("Hello World");
		hashTree.addDigest(data01);
		data02 = getDigest("H�llo W�rld");
		hashTree.addDigest(data02);
		data03 = getDigest("hello W�rld");
		hashTree.addDigest(data03);
		data04 = getDigest("should fail");

		hashTree.digestify();
		digestList01 = hashTree.getReducedTree(data01);
		hashTree.getReducedTree(data02); // should not fail
		
		verifier = new HashTreeVerifier(hashTree.getAggregatedDigest());
		wrongRootVerifier = new HashTreeVerifier(data04);
	}
	
	@Test
	public void testHashtree() throws GeneralSecurityException, IOException {
		assertEquals(6, digestList01.size());
		int fullSize = 0;
		for (List<byte[]> subList: digestList01) {
			fullSize += subList.size();
		}
		assertEquals(3, fullSize);
		verifier.verify(digestList01, data01);
	}
	
	@Test(expected = RuntimeException.class)
	public void testWrongTree() throws GeneralSecurityException, IOException {
		verifier.verify(digestList01, data02);		
	}
	
	@Test(expected = RuntimeException.class)
	public void testWrongDigest() throws GeneralSecurityException, IOException {
		hashTree.getReducedTree(data04);
	}
	
	@Test(expected = RuntimeException.class)
	public void testModifiedTree() throws GeneralSecurityException, IOException {
		digestList01.get(1).get(0)[0] += 1;
		verifier.verify(digestList01, data01);
	}
	
	@Test(expected = RuntimeException.class)
	public void testWrongRoot() throws GeneralSecurityException, IOException {
		wrongRootVerifier.verify(digestList01, data01);
	}
}
