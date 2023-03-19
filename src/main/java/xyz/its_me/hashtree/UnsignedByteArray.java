package xyz.its_me.hashtree;

import java.util.Arrays;

public class UnsignedByteArray implements Comparable<UnsignedByteArray> {
    private final byte[] array;

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
        for (int i = 0; i < array.length && result == 0; i++) {
            result = Integer.compare(array[i] & 0xFF, other.array[i] & 0xFF);
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UnsignedByteArray that = (UnsignedByteArray) o;
        return Arrays.equals(array, that.array);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(array);
    }
}
