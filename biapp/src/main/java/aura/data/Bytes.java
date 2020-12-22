package aura.data;

import android.util.Base64;

import java.io.Serializable;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.RandomAccess;

public class Bytes {

    private Bytes() {
    }

    /**
     * Returns a hash code for {@code value}; equal to the result of invoking
     * {@code ((Byte)
     * value).hashCode()}.
     * <p>
     * <p>
     * <b>Java 8 users:</b> use {@link Byte#hashCode(byte)} instead.
     *
     * @param value a primitive {@code byte} value
     * @return a hash code for the value
     */
    public static int hashCode(byte value) {
        return value;
    }

    /**
     * Returns {@code true} if {@code target} is present as an element anywhere in
     * {@code array}.
     *
     * @param array  an array of {@code byte} values, possibly empty
     * @param target a primitive {@code byte} value
     * @return {@code true} if {@code array[i] == target} for some value of
     * {@code i}
     */
    public static boolean contains(byte[] array, byte target) {
        for (byte value : array) {
            if (value == target) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the index of the first appearance of the value {@code target} in
     * {@code array}.
     *
     * @param array  an array of {@code byte} values, possibly empty
     * @param target a primitive {@code byte} value
     * @return the least index {@code i} for which {@code array[i] == target}, or
     * {@code -1} if no such index exists.
     */
    public static int indexOf(byte[] array, byte target) {
        return indexOf(array, target, 0, array.length);
    }

    private static int indexOf(byte[] array, byte target, int start, int end) {
        for (int i = start; i < end; i++) {
            if (array[i] == target) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Returns the start position of the first occurrence of the specified
     * {@code target} within {@code array}, or {@code -1} if there is no such
     * occurrence.
     * <p>
     * <p>
     * More formally, returns the lowest index {@code i} such that
     * {@code Arrays.copyOfRange(array,
     * i, i + target.length)} contains exactly the same elements as {@code target}.
     *
     * @param array  the array to search for the sequence {@code target}
     * @param target the array to search for as a sub-sequence of {@code array}
     */
    public static int indexOf(byte[] array, byte[] target) {
        Preconditions.checkNotNull(array, "array");
        Preconditions.checkNotNull(target, "target");
        if (target.length == 0) {
            return 0;
        }

        outer:
        for (int i = 0; i < array.length - target.length + 1; i++) {
            for (int j = 0; j < target.length; j++) {
                if (array[i + j] != target[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * Returns the index of the last appearance of the value {@code target} in
     * {@code array}.
     *
     * @param array  an array of {@code byte} values, possibly empty
     * @param target a primitive {@code byte} value
     * @return the greatest index {@code i} for which {@code array[i] == target}, or
     * {@code -1} if no such index exists.
     */
    public static int lastIndexOf(byte[] array, byte target) {
        return lastIndexOf(array, target, 0, array.length);
    }

    private static int lastIndexOf(byte[] array, byte target, int start, int end) {
        for (int i = end - 1; i >= start; i--) {
            if (array[i] == target) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Returns the values from each provided array combined into a single array. For
     * example, {@code concat(new byte[] {a, b}, new byte[] {}, new byte[] {c}}
     * returns the array {@code {a, b, c}}.
     *
     * @param arrays zero or more {@code byte} arrays
     * @return a single array containing all the values from the source arrays, in
     * order
     */
    public static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    /**
     * Returns an array containing the same values as {@code array}, but guaranteed
     * to be of a specified minimum length. If {@code array} already has a length of
     * at least {@code minLength}, it is returned directly. Otherwise, a new array
     * of size {@code minLength + padding} is returned, containing the values of
     * {@code array}, and zeroes in the remaining places.
     *
     * @param array     the source array
     * @param minLength the minimum length the returned array must guarantee
     * @param padding   an extra amount to "grow" the array by if growth is
     *                  necessary
     * @return an array containing the values of {@code array}, with guaranteed
     * minimum length {@code
     * minLength}
     * @throws IllegalArgumentException if {@code minLength} or {@code padding} is
     *                                  negative
     */
    public static byte[] ensureCapacity(byte[] array, int minLength, int padding) {
        Preconditions.checkArgument(minLength >= 0, "Invalid minLength: %s", minLength);
        Preconditions.checkArgument(padding >= 0, "Invalid padding: %s", padding);
        return (array.length < minLength) ? Arrays.copyOf(array, minLength + padding) : array;
    }

    /**
     * Returns an array containing each value of {@code collection}, converted to a
     * {@code byte} value in the manner of {@link Number#byteValue}.
     * <p>
     * <p>
     * Elements are copied from the argument collection as if by
     * {@code collection.toArray()}. Calling this method is as thread-safe as
     * calling that method.
     *
     * @param collection a collection of {@code Number} instances
     * @return an array containing the same values as {@code collection}, in the
     * same order, converted to primitives
     * @throws NullPointerException if {@code collection} or any of its elements is
     *                              null
     * @since 1.0 (parameter was {@code Collection<Byte>} before 12.0)
     */
    public static byte[] toArray(Collection<? extends Number> collection) {
        if (collection instanceof ByteArrayAsList) {
            return ((ByteArrayAsList) collection).toByteArray();
        }

        Object[] boxedArray = collection.toArray();
        int len = boxedArray.length;
        byte[] array = new byte[len];
        for (int i = 0; i < len; i++) {
            // checkNotNull for GWT (do not optimize)
            array[i] = ((Number) Preconditions.checkNotNull(boxedArray[i])).byteValue();
        }
        return array;
    }

    /**
     * Compare the elements in give range of two arrays.
     * <p>
     * If the data length to compare is less then the given compare length, the
     * result wil be {@code false}.
     *
     * @param data1  data1 to compare.
     * @param data2  data2 to compare.
     * @param start  compare start index.
     * @param length length to compre.
     * @return equal or not.
     */
    public static boolean equals(byte[] data1, byte[] data2, int start, int length) {
        if (data1 == data2) {
            return true;
        }

        if (length < 0) {
            throw new IllegalArgumentException("Length to compare should >=0.");
        }

        int end = start + length - 1;
        if (end > data1.length - 1 || end > data1.length - 1) {
            return false;
        }

        for (int i = start; i <= end; i++) {
            if (data1[i] != data2[i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check all the elements in the two give bytes is equal.
     *
     * @param data1 data1 to compare.
     * @param data2 data2 to compare.
     * @return equal or not.
     */
    public static boolean equals(byte[] data1, byte[] data2) {
        return Arrays.equals(data1, data2);
    }

    /**
     * Returns a fixed-size list backed by the specified array, similar to
     * {@link Arrays#asList(Object[])}. The list supports
     * {@link List#set(int, Object)}, but any attempt to set a value to {@code null}
     * will result in a {@link NullPointerException}.
     * <p>
     * <p>
     * The returned list maintains the values, but not the identities, of
     * {@code Byte} objects written to or read from it. For example, whether
     * {@code list.get(0) == list.get(0)} is true for the returned list is
     * unspecified.
     *
     * @param backingArray the array to back the list
     * @return a list view of the array
     */
    public static List<Byte> asList(byte... backingArray) {
        if (backingArray.length == 0) {
            return Collections.emptyList();
        }
        return new ByteArrayAsList(backingArray);
    }

    private static class ByteArrayAsList extends AbstractList<Byte> implements RandomAccess, Serializable {
        final byte[] array;
        final int start;
        final int end;

        ByteArrayAsList(byte[] array) {
            this(array, 0, array.length);
        }

        ByteArrayAsList(byte[] array, int start, int end) {
            this.array = array;
            this.start = start;
            this.end = end;
        }

        @Override
        public int size() {
            return end - start;
        }

        @Override
        public boolean isEmpty() {
            return false;
        }

        @Override
        public Byte get(int index) {
            Preconditions.checkElementIndex(index, size());
            return array[start + index];
        }

        @Override
        public boolean contains(Object target) {
            // Overridden to prevent a ton of boxing
            return (target instanceof Byte) && Bytes.indexOf(array, (Byte) target, start, end) != -1;
        }

        @Override
        public int indexOf(Object target) {
            // Overridden to prevent a ton of boxing
            if (target instanceof Byte) {
                int i = Bytes.indexOf(array, (Byte) target, start, end);
                if (i >= 0) {
                    return i - start;
                }
            }
            return -1;
        }

        @Override
        public int lastIndexOf(Object target) {
            // Overridden to prevent a ton of boxing
            if (target instanceof Byte) {
                int i = Bytes.lastIndexOf(array, (Byte) target, start, end);
                if (i >= 0) {
                    return i - start;
                }
            }
            return -1;
        }

        @Override
        public Byte set(int index, Byte element) {
            Preconditions.checkElementIndex(index, size());
            byte oldValue = array[start + index];
            // checkNotNull for GWT (do not optimize)
            array[start + index] = Preconditions.checkNotNull(element);
            return oldValue;
        }

        @Override
        public List<Byte> subList(int fromIndex, int toIndex) {
            int size = size();
            Preconditions.checkPositionIndexes(fromIndex, toIndex, size);
            if (fromIndex == toIndex) {
                return Collections.emptyList();
            }
            return new ByteArrayAsList(array, start + fromIndex, start + toIndex);
        }

        @Override
        public boolean equals(Object object) {
            if (object == this) {
                return true;
            }
            if (object instanceof ByteArrayAsList) {
                ByteArrayAsList that = (ByteArrayAsList) object;
                int size = size();
                if (that.size() != size) {
                    return false;
                }
                for (int i = 0; i < size; i++) {
                    if (array[start + i] != that.array[that.start + i]) {
                        return false;
                    }
                }
                return true;
            }
            return super.equals(object);
        }

        @Override
        public int hashCode() {
            int result = 1;
            for (int i = start; i < end; i++) {
                result = 31 * result + Bytes.hashCode(array[i]);
            }
            return result;
        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder(size() * 5);
            builder.append('[').append(array[start]);
            for (int i = start + 1; i < end; i++) {
                builder.append(", ").append(array[i]);
            }
            return builder.append(']').toString();
        }

        byte[] toByteArray() {
            return Arrays.copyOfRange(array, start, end);
        }

        private static final long serialVersionUID = 0;
    }

    /**
     * Reverses the elements of {@code array}. This is equivalent to {@code
     * Collections.reverse(Bytes.asList(array))}, but is likely to be more
     * efficient.
     *
     * @since 23.1
     */
    public static void reverse(byte[] array) {
        Preconditions.checkNotNull(array);
        reverse(array, 0, array.length);
    }

    /**
     * Reverses the elements of {@code array} between {@code fromIndex} inclusive
     * and {@code toIndex} exclusive. This is equivalent to {@code
     * Collections.reverse(Bytes.asList(array).subList(fromIndex, toIndex))}, but is
     * likely to be more efficient.
     *
     * @throws IndexOutOfBoundsException if {@code fromIndex < 0},
     *                                   {@code toIndex > array.length}, or
     *                                   {@code toIndex > fromIndex}
     * @since 23.1
     */
    public static void reverse(byte[] array, int fromIndex, int toIndex) {
        Preconditions.checkNotNull(array);
        Preconditions.checkPositionIndexes(fromIndex, toIndex, array.length);
        for (int i = fromIndex, j = toIndex - 1; i < j; i++, j--) {
            byte tmp = array[i];
            array[i] = array[j];
            array[j] = tmp;
        }
    }

    /**
     * Byte array to hex string with default no separator.
     * <p>
     * Each byte in the array converted to a 2-character hex string with upper case.
     * <p>
     * Examples: <blockquote>
     *
     * <pre>
     * new byte[]{1, 32, 127} -> "01207F"
     * new byte[]{10, 11, 26} -> "0A0B1A"
     * </pre>
     *
     * </blockquote>
     *
     * @param data data
     * @return string.
     * @see #fromHexString(String)
     */
    public static String toHexString(byte[] data) {
        return toHexString(data, "");
    }

    /**
     * Byte array to hex string.
     * <p>
     * Each byte in the array converted to a 2-character hex string with upper case.
     * <p>
     * Examples: <blockquote>
     *
     * <pre>
     * new byte[]{1, 32, 127} -> "01207F"
     * new byte[]{10, 11, 26} -> "0A0B1A"
     * </pre>
     *
     * </blockquote>
     *
     * @param data data.
     * @return string.
     * @see #fromHexString(String)
     */
    public static String toHexString(byte[] data, String separator) {
        StringBuilder buffer = new StringBuilder();

        for (int i = 0; i < data.length; i++) {
            buffer.append(String.format("%02x", data[i]).toUpperCase());

            // not insert separator after the last
            if (!Strings.isNullOrEmpty(separator) && i < data.length - 1) {
                buffer.append(separator);
            }
        }

        return buffer.toString();
    }

    /**
     * Convert a byte to hex string.
     *
     * @param b byte value.
     * @return hex string.
     * @see #toHexString(byte)
     */
    public static String toHexString(byte b) {
        return toHexString(new byte[]{b});
    }

    /**
     * Convert a hex string to a byte array with default align {@link #ALIGN_RIGHT}
     * and defalt padding '0'.
     * <p>
     * Examples:
     *
     * <pre>
     * {@code
     * fromHexString("01207F") -> new byte[]{0x1, 0x20, 0x7F}
     * fromHexString("0A0B1A") -> new byte[]{10, 11, 26}
     *
     *  // odd bit, default padding and align.
     * fromHexString("A02") -> new byte[]{(byte) 0xA0, 0x20};
     * }
     * </pre>
     *
     * @param data hex string.
     * @return the hex byte corresponding to the hex string.
     * @see #toHexString(byte[])
     */
    public static byte[] fromHexString(String data) {
        return fromHexString(data, ALIGN.ALIGN_LEFT, '0');
    }

    /**
     * Convert a hex string to a byte array with default padding '0'.
     * <p>
     * Examples:
     *
     * <pre>
     * {@code
     * Bytes.fromHexString("0a7", Bytes.ALIGN_LEFT, '0') -> new byte[]{0x0a, (byte) 0x70}
     * Bytes.fromHexString("0a7", Bytes.ALIGN_RIGHT, '0') -> new byte[]{0x0, (byte) 0xa7}
     * }
     * </pre>
     *
     * @param data  hex string.
     * @param align align with available values in {@link ALIGN}
     * @return hex byte array.
     * @see #fromHexString(String, int, char)
     * @see #fromHexString(String)
     */
    public static byte[] fromHexString(String data, ALIGN align) {
        return fromHexString(data, align, '0');
    }

    /**
     * Convert a hex string to a byte array. The hex string can be in lower case or
     * upper case.
     * <p>
     * Each 2 character will be converted to a byte. The first is high 4 bits, the
     * other is low 4 bits. If the length of the data is odd, then it will be padded
     * "0" according to the padding direction. If the length is odd, but padding
     * direction is none, then a {@link IllegalArgumentException} will be raised.
     * <p>
     * Examples:
     *
     * <pre>
     * {@code
     * Bytes.fromHexString("0a7", Bytes.ALIGN_LEFT, '0') -> new byte[]{0x0a, (byte) 0x70}
     * Bytes.fromHexString("0a7", Bytes.ALIGN_RIGHT, '0') -> new byte[]{0x0, (byte) 0xa7}
     * }
     * </pre>
     *
     * @param data    hex string.
     * @param align   align with available values in {@link ALIGN}
     * @param padding padding character.
     * @return hex byte array.
     * @see #toHexString(byte[], String)
     * @see #fromHexString(String)
     * @see #fromHexString(String, int)
     */
    public static byte[] fromHexString(String data, ALIGN align, char padding) {
        byte[] result = new byte[(data.length() + 1) / 2];

        // if the length of the string is odd.
        if ((data.length() & 0x1) == 1) {
            // if yes, then add "0" on the right(low bit).
            // actually, it may not the perfect way to process odd string.
            switch (align) {
                case ALIGN_RIGHT:
                    data = padding + data;
                    break;
                case ALIGN_LEFT:
                    data = data + padding;
                    break;
                default:
                    throw new IllegalArgumentException("The length of data should be even");
            }
        }

        for (int i = 0; i < result.length; i++) {
            result[i] = ((byte) (fromHexAscii(data.charAt(i * 2 + 1)) | fromHexAscii(data.charAt(i * 2)) << 4));
        }
        return result;
    }

    /**
     * A ascii character to it's value.
     * <p>
     * The asc character should in ranges ['0'-'9'], ['a'-'f'], ['A'-'F']
     * <p>
     * Examples:
     * <p>
     * <blockquote>
     *
     * <pre>
     * 'a' -> 10
     * 'F' -> 15
     * '2' -> 2
     * </pre>
     *
     * </blockquote>
     *
     * @param ascii
     * @return the result byte.
     * @see #fromHexString(String)
     */
    static byte fromHexAscii(char ascii) {
        if ((ascii <= 'f') && (ascii >= 'a')) {
            return (byte) (ascii - 'a' + 10);
        }

        if ((ascii <= 'F') && (ascii >= 'A')) {
            return (byte) (ascii - 'A' + 10);
        }

        if ((ascii <= '9') && (ascii >= '0')) {
            return (byte) (ascii - '0');
        }

        throw new IllegalArgumentException("The hex char in the argument is not valid.");
    }

    /**
     * A ascii byte to it's value.
     * <p>
     * The asc character should in ranges ['0'-'9'], ['a'-'f'], ['A'-'F']
     * <p>
     * Examples:
     * <p>
     * <blockquote>
     *
     * <pre>
     * 'a' -> 10
     * 'F' -> 15
     * '2' -> 2
     * </pre>
     *
     * </blockquote>
     *
     * @param ascii
     * @return the result byte.
     * @see #fromHexString(String)
     */
    private static byte fromHexAscii(byte ascii) {
        return fromHexAscii((char) ascii);
    }

    /**
     * Extract sub bytes from given start index.
     *
     * @param data       data to be operate.
     * @param startIndex the startIndex index, it should be in range [0, length-1]
     * @return the sub bytes.
     */
    public static byte[] subBytes(byte[] data, int startIndex) {
        return subBytes(data, startIndex, data.length);

    }

    /**
     * Extract sub bytes from a given data according to a range.
     * <p>
     * If the sub length is more then the training data length, then give all the
     * remaining length.
     *
     * @param data       data to be operate.
     * @param startIndex the startIndex index, it should be in range [0, length-1]
     * @param length     the length to extract.
     * @return the sub bytes.
     */
    public static byte[] subBytes(byte[] data, int startIndex, int length) {
        if ((startIndex < 0) || (data.length <= startIndex) || length < 0) {
            return new byte[0];
        }

        // if there is no enough data.
        if ((data.length < startIndex + length)) {
            // then fill all the remaining data.
            length = data.length - startIndex;
        }

        byte[] ret = new byte[length];

        System.arraycopy(data, startIndex, ret, 0, length);
        return ret;
    }

    /**
     * Convert a byte array with {@link #BIG_ENDIAN} to an integer.
     * <p>
     * The length of the byte array should be <= 4. Often used to calculate length
     * according to some bytes.
     * <p>
     * If we have 4 length bytes, then the integer should be:
     *
     * <pre>
     * __ __ __ __ = b1 b2 b3 b4
     * </pre>
     * <p>
     * For examples:
     *
     * <blockquote>
     *
     * <pre>
     * new byte[]{1, 2, 3} -> 66051.
     * new byte[]{1, 2} -> 258.
     * </pre>
     *
     * </blockquote>
     *
     * @param data byte array data.
     * @return int value.
     * @see #toInt(byte[], int)
     */

    public static int toInt(byte[] data) {
        return toInt(data, ENDIAN.BIG_ENDIAN);
    }

    /**
     * Convert a byte array with {@link #BIG_ENDIAN} to an integer.
     * <p>
     * The length of the byte array should be <= 4. Often used to calculate length
     * according to some bytes.
     * <p>
     * If we have 4 length bytes, then the integer should be with big endian:
     *
     * <pre>
     * __ __ __ __ = b1 b2 b3 b4
     * </pre>
     * <p>
     * For examples:
     *
     * <blockquote>
     *
     * <pre>
     * new byte[]{1, 2, 3} -> 66051 with big endian.
     * new byte[]{1, 2} -> 258 with big endian.
     * </pre>
     *
     * </blockquote>
     *
     * @param data byte array data.
     * @return int value.
     * @see #fromInt(int, int, int)
     */
    public static int toInt(byte[] data, ENDIAN endian) {
        if (data.length > 4) {
            throw new IllegalArgumentException("The length of the data should be <= 4");
        }

        int lastIndex = data.length - 1;
        int result = 0;
        for (int i = 0; i < data.length; i++) {
            // big endian
            int byteIndex = lastIndex - i;

            if (endian == ENDIAN.LITTLE_ENDIAN) {
                byteIndex = i;
            }

            // << 3 means *8
            int bitIndex = byteIndex << 3;

            // |= means +=
            result |= (data[i] & 0xFF) << bitIndex;
        }

        return result;
    }

    /**
     * Convert an integer value to a byte array with given length and
     * {@link #BIG_ENDIAN}.
     * <p>
     * The integer value will be split into 4 byte blocks which is the result array.
     * Often used to calculate length according to some bytes.
     * <p>
     * The length of the byte array should be <= 4. It mean that if the byte array
     * length is 2, then the higher 2 bytes of the integer will be ignored.
     * <p>
     * <p>
     * For examples:
     * <p>
     * <blockquote>
     *
     * <pre>
     * 66051(length = 4) -> new byte[]{1, 2, 3}
     * 258(length=2) -> new byte[]{1, 2}
     * </pre>
     *
     * </blockquote>
     *
     * @param value  integer value.
     * @param length the length of the byte array.
     * @return the converted byte array.
     * @see #toInt(byte[], int)
     * @see #toInt(byte[])
     */
    public static byte[] fromInt(int value, int length) {
        return fromInt(value, length, ENDIAN.BIG_ENDIAN);
    }

    /**
     * Convert an integer value to a 4-length byte array with given length and
     * {@link #BIG_ENDIAN}.
     *
     * @param value
     * @return byte array.
     * @see #toInt(byte[], int)
     * @see #toInt(byte[])
     */
    public static byte[] fromInt(int value) {
        return fromInt(value, 4, ENDIAN.BIG_ENDIAN);
    }

    /**
     * Convert an integer value to a byte array with given length.
     * <p>
     * The integer value will be split into 4 byte blocks which is the result array.
     * Often used to calculate length according to some bytes.
     * <p>
     * The length of the byte array should be <= 4. It mean that if the byte array
     * length is 2, then the higher 2 bytes of the integer will be ignored.
     * <p>
     * <p>
     * For examples:
     * <p>
     * <blockquote>
     *
     * <pre>
     * 66051(length = 4) -> new byte[]{1, 2, 3} with high endian.
     * 258(length=2) -> new byte[]{1, 2} with high endian.
     * </pre>
     *
     * </blockquote>
     *
     * @param value  integer value.
     * @param length the length of the byte array.
     * @param endian the byte order {@link ENDIAN}.
     * @return the converted byte array.
     * @see #toInt(byte[], int)
     * @see #toInt(byte[])
     * @see ENDIAN
     */
    public static byte[] fromInt(int value, int length, ENDIAN endian) {
        if (length > 4 || length < 1) {
            throw new IllegalArgumentException("The length in argument should be in range [1, 4]");
        }

        byte[] bytes = new byte[length];

        for (int i = 0; i <= length - 1; i++) {
            // byte index to operate. If the length is 4 and index 0, then the byteIndex = 3
            int byteIndex = (length - 1 - i);

            // bit length to move to right
            // <<3 mean *8
            int bitLength = byteIndex << 3;

            // move the byte to operate to rightest position and mask
            int byteValue = (value >> bitLength) & 0xFF;

            // little endian
            if (endian == ENDIAN.LITTLE_ENDIAN) {
                bytes[byteIndex] = (byte) byteValue;
            } else {
                // big endian
                bytes[i] = (byte) byteValue;
            }
        }

        return bytes;
    }

    /**
     * Shrink a ascii byte array to hex array.
     * <p>
     * Convert 2 ascii bytes to hex string bytes. The length of the ascii bytes
     * should be event.
     * <p>
     * For examples:
     * <p>
     *
     * <pre>
     * {@code
     * new byte[]{0x31, 0x32, 0x32, 0x61} -> new byte[]{0x12, 0x02a}
     * }
     * </pre>
     *
     * @param asciis ascii byte array.
     * @return byte array.
     */
    public static byte[] shrink(byte[] asciis) {
        if (asciis.length % 2 != 0) {
            throw new IllegalArgumentException("The length of the ascii array should be even.");
        }

        byte[] hexes = new byte[asciis.length / 2];

        for (int i = 0; i < asciis.length; ) {
            // high byte
            byte highByte = fromHexAscii(asciis[(i++)]);

            // low byte
            byte lowByte = fromHexAscii(asciis[i++]);

            int index = (i - 1) / 2;
            hexes[index] = (byte) ((highByte << 4) + lowByte);
        }
        return hexes;
    }

    /**
     * Check if the bit on the given position is true or not.
     * <p>
     * The range to the position is [1, 8] from left to right.
     *
     * @param value    byte value.
     * @param position position of the byte to test.
     * @return {@code true} = 1, {@code false} = 0.
     */
    public static boolean getBit(byte value, int position) {
        if ((position < 1) || (position > 8)) {
            throw new IllegalArgumentException("parameter 'bitPos' must be between 1 and 8. bitPos=" + position);
        }
        return (value >> 8 - position & 0x1) == 1;
    }

    /**
     * Convert signed byte to unsigned, and get a int.
     * <p>
     * Examples:
     * <p>
     *
     * <pre>
     * {@code
     *      -127 -> 2
     *      -1 -> 255
     *      127 -> 127
     * }
     * </pre>
     *
     * @param data byte value.
     * @return int value.
     */
    public static final int toUnsigned(byte data) {
        return data & 0xFF;
    }

    /**
     * Check if the bytes is empty.
     *
     * @param array the bytes data to be checked
     * @return true or false
     */
    public static boolean isNullOrEmpty(byte[] array) {
        return (array == null) || (array.length == 0);
    }

    /**
     * Byte A xor Byte B
     *
     * @param a byte A
     * @param b byte B
     * @return
     */
    public static byte xor(byte a, byte b) {
        return (byte) (a ^ b);
    }

    /**
     * Byte Array A xor Byte Array B
     *
     * @param a byte array A
     * @param b byte array B
     * @return
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("the parameters length ara different.");
        }
        byte[] xor = new byte[a.length];
        for (int i = 0; i < xor.length; i++) {
            xor[i] = xor(a[i], b[i]);
        }
        return xor;
    }

    /***
     * check lrc
     *
     * @param a
     * @return
     */
    public static byte lrc(byte[] a) {
        byte lrc = 0x00;
        for (int i = 0; i < a.length; i++) {
            if (i == 0) {
                lrc = a[i];
                continue;
            }
            lrc = xor(lrc, a[i]);
        }
        return lrc;
    }

    /**
     * 转2进制字符串
     *
     * @param b
     * @return
     */
    public static String toBitString(byte b) {
        return ""
                + (byte) ((b >> 7) & 0x1) + (byte) ((b >> 6) & 0x1)
                + (byte) ((b >> 5) & 0x1) + (byte) ((b >> 4) & 0x1)
                + (byte) ((b >> 3) & 0x1) + (byte) ((b >> 2) & 0x1)
                + (byte) ((b >> 1) & 0x1) + (byte) ((b >> 0) & 0x1);
    }

    /**
     * 转2进制字符串
     *
     * @param data
     * @return
     */
    public static String toBitString(byte[] data) {
        StringBuffer buffer = new StringBuffer();
        for (byte b : data) {
            buffer.append(toBitString(b));
        }
        return buffer.toString();
    }

    /**
     * 二进制字符串转字节
     *
     * @param bit
     * @return
     * @throws IllegalAccessException
     */
    public static byte[] bitString2Byte(String bit) throws IllegalArgumentException {
        if (Strings.isNullOrEmpty(bit) || bit.length() % 8 != 0) {
            throw new IllegalArgumentException("The bit string is not valid.");
        }
        byte[] result = new byte[bit.length() / 8];
        for (int i = 0; i < bit.length() / 8; i++) {
            String tmp = bit.substring(i * 8, (i + 1) * 8);
            result[i] = (byte) Short.parseShort(tmp, 2);
        }
        return result;
    }

    /**
     * @param base64String
     * @return
     */
    public static byte[] fromBase64String(String base64String) {
        return Base64.decode(base64String, Base64.DEFAULT);
    }

    /**
     * @param data
     * @return
     */
    public static String toBase64String(byte[] data) {
        return Base64.encodeToString(data, Base64.DEFAULT);
    }

    /**
     * 获得DER长度
     *
     * @param value
     * @return
     * @throws IllegalArgumentException
     */
    public static byte[] getDERLen(int value) throws IllegalArgumentException {
        if ((value & 0xFF) < 0x00) {
            throw new IllegalArgumentException("The value must large than 0.");
        } else {
            if ((value & 0xFF) < 0x80) {
                return Bytes.fromInt(value, 1);
            } else if ((value & 0xFF) <= 0xFF) {
                return Bytes.concat(new byte[]{(byte) 0x81}, Bytes.fromInt(value, 1));
            } else if ((value & 0xFFFF) <= 0xFFFF) {
                return Bytes.concat(new byte[]{(byte) 0x82}, Bytes.fromInt(value, 2));
            } else {
                throw new IllegalArgumentException("The value is too large");
            }
        }
    }

    public enum ENDIAN {
        BIG_ENDIAN, LITTLE_ENDIAN
    }

    public enum ALIGN {
        ALIGN_LEFT, ALIGN_RIGHT
    }
}