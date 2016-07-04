package com.westernacher.hashtree;

public class UnsignedByteArray implements Comparable<UnsignedByteArray> {
	final private byte[] array;

	public byte[] getArray() {
		return array;
	}
	
	UnsignedByteArray(byte[] array) {
		this.array = array;
	}

	@Override
	public int compareTo(UnsignedByteArray other) {
		if (array.length != other.array.length) {
			throw new RuntimeException("arrays have different lengths: " + array.length + " vs. " + other.array.length);
		}
		int result = 0;
		for (int i = 0; i < array.length && result == 0; i ++) {
			Integer left = new Integer(array[i] & 0xFF);
			Integer right = new Integer(other.array[i] & 0xFF);
			result = left.compareTo(right);
		}
		return result;
	}
}
