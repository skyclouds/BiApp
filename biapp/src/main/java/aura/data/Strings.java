package aura.data;

import java.io.UnsupportedEncodingException;
import java.util.regex.Pattern;

import static aura.data.Preconditions.checkArgument;
import static aura.data.Preconditions.checkNotNull;

/**
 * Static utility methods pertaining to {@code String} or {@code CharSequence}
 * instances.
 *
 * @author Kevin Bourrillion
 * @author feiq
 * @since 2.0
 */
public final class Strings {
    /**
     * IP regex pattern.
     */
    private static final Pattern IP_PATTERN = Pattern
            .compile("^((25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)$");

    /**
     * Port regex pattern.
     */
    private static final Pattern PORT_PATTERN = Pattern
            .compile("^([0-9]|[1-9]\\d{1,3}|[1-5]\\d{4}|6[0-5]{2}[0-3][0-5])$");

    /**
     * Http url pattern.
     */
    private static final Pattern HTTPS_URL_PATTERN = Pattern.compile("^[hH][tT]{2}[pP][sS]://[\\S]*");

    /**
     * Https url pattern.
     */
    private static final Pattern HTTP_URL_PATTERN = Pattern.compile("^[hH][tT]{2}[pP]://[\\S]*");

    private Strings() {
    }

    /**
     * Returns the given string if it is non-null; the empty string otherwise.
     *
     * @param string the string to test and possibly return
     * @return {@code string} itself if it is non-null; {@code ""} if it is null
     */
    public static String nullToEmpty(String string) {
        return (string == null) ? "" : string;
    }

    /**
     * Returns the given string if it is nonempty; {@code null} otherwise.
     *
     * @param string the string to test and possibly return
     * @return {@code string} itself if it is nonempty; {@code null} if it is empty
     *         or null
     */
    public static String emptyToNull(String string) {
        return isNullOrEmpty(string) ? null : string;
    }

    /**
     * Returns {@code true} if the given string is null or is the empty string.
     * <p>
     * <p>
     * Consider normalizing your string references with {@link #nullToEmpty}. If you
     * do, you can use {@link String#isEmpty()} instead of this method, and you
     * won't need special null-safe forms of methods like {@link String#toUpperCase}
     * either. Or, if you'd like to normalize "in the other direction," converting
     * empty strings to {@code null}, you can use {@link #emptyToNull}.
     *
     * @param string a string reference to check
     * @return {@code true} if the string is null or is the empty string
     */
    public static boolean isNullOrEmpty(String string) {
        return string == null || string.isEmpty();
    }

    /**
     * Returns a string, of length at least {@code minLength}, consisting of
     * {@code string} prepended with as many copies of {@code padChar} as are
     * necessary to reach that length. For example,
     * <p>
     * <ul>
     * <li>{@code padStart("7", 3, '0')} returns {@code "007"}
     * <li>{@code padStart("2010", 3, '0')} returns {@code "2010"}
     * </ul>
     * <p>
     * <p>
     * See {@link java.util.Formatter} for a richer set of formatting capabilities.
     *
     * @param string    the string which should appear at the end of the result
     * @param minLength the minimum length the resulting string must have. Can be
     *                  zero or negative, in which case the input string is always
     *                  returned.
     * @param padChar   the character to insert at the beginning of the result until
     *                  the minimum length is reached
     * @return the padded string
     */
    public static String padStart(String string, int minLength, char padChar) {
        checkNotNull(string);
        if (string.length() >= minLength) {
            return string;
        }
        StringBuilder sb = new StringBuilder(minLength);
        for (int i = string.length(); i < minLength; i++) {
            sb.append(padChar);
        }
        sb.append(string);
        return sb.toString();
    }

    /**
     * Returns a string, of length at least {@code minLength}, consisting of
     * {@code string} appended with as many copies of {@code padChar} as are
     * necessary to reach that length. For example,
     * <p>
     * <ul>
     * <li>{@code padEnd("4.", 5, '0')} returns {@code "4.000"}
     * <li>{@code padEnd("2010", 3, '!')} returns {@code "2010"}
     * </ul>
     * <p>
     * <p>
     * See {@link java.util.Formatter} for a richer set of formatting capabilities.
     *
     * @param string    the string which should appear at the beginning of the
     *                  result
     * @param minLength the minimum length the resulting string must have. Can be
     *                  zero or negative, in which case the input string is always
     *                  returned.
     * @param padChar   the character to append to the end of the result until the
     *                  minimum length is reached
     * @return the padded string
     */
    public static String padEnd(String string, int minLength, char padChar) {
        checkNotNull(string);
        if (string.length() >= minLength) {
            return string;
        }
        StringBuilder sb = new StringBuilder(minLength);
        sb.append(string);
        for (int i = string.length(); i < minLength; i++) {
            sb.append(padChar);
        }
        return sb.toString();
    }

    /**
     * Returns a string consisting of a specific number of concatenated copies of an
     * input string. For example, {@code repeat("hey", 3)} returns the string
     * {@code "heyheyhey"}.
     *
     * @param string any non-null string
     * @param count  the number of times to repeat it; a nonnegative integer
     * @return a string containing {@code string} repeated {@code count} times (the
     *         empty string if {@code count} is zero)
     * @throws IllegalArgumentException if {@code count} is negative
     */
    public static String repeat(String string, int count) {
        checkNotNull(string);

        if (count <= 1) {
            checkArgument(count >= 0, "invalid count: %s", count);
            return (count == 0) ? "" : string;
        }

        // IF YOU MODIFY THE CODE HERE, you must update StringsRepeatBenchmark
        final int len = string.length();
        final long longSize = (long) len * (long) count;
        final int size = (int) longSize;
        if (size != longSize) {
            throw new ArrayIndexOutOfBoundsException("Required array size too large: " + longSize);
        }

        final char[] array = new char[size];
        string.getChars(0, len, array, 0);
        int n;
        for (n = len; n < size - n; n <<= 1) {
            System.arraycopy(array, 0, array, n, n);
        }
        System.arraycopy(array, 0, array, n, size - n);
        return new String(array);
    }

    /**
     * Returns the longest string {@code prefix} such that
     * {@code a.toString().startsWith(prefix) &&
     * b.toString().startsWith(prefix)}, taking care not to split surrogate pairs.
     * If {@code a} and {@code b} have no common prefix, returns the empty string.
     *
     * @since 11.0
     */
    public static String commonPrefix(CharSequence a, CharSequence b) {
        checkNotNull(a);
        checkNotNull(b);

        int maxPrefixLength = Math.min(a.length(), b.length());
        int p = 0;
        while (p < maxPrefixLength && a.charAt(p) == b.charAt(p)) {
            p++;
        }
        if (validSurrogatePairAt(a, p - 1) || validSurrogatePairAt(b, p - 1)) {
            p--;
        }
        return a.subSequence(0, p).toString();
    }

    /**
     * Returns the longest string {@code suffix} such that
     * {@code a.toString().endsWith(suffix) &&
     * b.toString().endsWith(suffix)}, taking care not to split surrogate pairs. If
     * {@code a} and {@code b} have no common suffix, returns the empty string.
     *
     * @since 11.0
     */
    public static String commonSuffix(CharSequence a, CharSequence b) {
        checkNotNull(a);
        checkNotNull(b);

        int maxSuffixLength = Math.min(a.length(), b.length());
        int s = 0;
        while (s < maxSuffixLength && a.charAt(a.length() - s - 1) == b.charAt(b.length() - s - 1)) {
            s++;
        }
        if (validSurrogatePairAt(a, a.length() - s - 1) || validSurrogatePairAt(b, b.length() - s - 1)) {
            s--;
        }
        return a.subSequence(a.length() - s, a.length()).toString();
    }

    /**
     * True when a valid surrogate pair starts at the given {@code index} in the
     * given {@code string}. Out-of-range indexes return false.
     */
    static boolean validSurrogatePairAt(CharSequence string, int index) {
        return index >= 0 && index <= (string.length() - 2) && Character.isHighSurrogate(string.charAt(index))
                && Character.isLowSurrogate(string.charAt(index + 1));
    }

    /**
     * Check if the given string is numeric.
     * <p>
     * For examples: It's numbers {@code 1}, {@code -1}, {@code 123}
     *
     * @param string string.
     * @return is number string or not.
     */
    public static boolean isNumeric(String string) {
        return Ints.tryParse(string) != null;
    }

    /**
     * Filter digits string from a raw string not including decimal point.
     * <p>
     * For examples:
     * <p>
     * 
     * <pre>
     * {@code
     * "12.32" -> "1232"
     * "a1b2c3d" -> "123"
     *
     * }
     * </pre>
     */
    public static String extractDigits(String data) {
        StringBuffer sb = new StringBuffer();
        if (isNumeric(data)) {
            return data.replace(".", "");
        }

        for (int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            if (c <= '9' && c >= '0') {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Mask a string with the given mask pattern.
     * <p>
     * The mask pattern is a string made up by "x' or 'X' and '*'.
     * <ul>
     * <li>'x' or 'X' means the character in the same position should not be
     * masked.</li>
     * <li>'*' means the character in the same position should not be masked.</li>
     * </ul>
     * <p>
     * Examples:
     * <p>
     * 
     * <pre>
     * {@code
     *
     * String data = "1234123412341234";
     *
     * "xxxx****xxxxxxxx" -> "1234****12341234"
     * "xx*xx" -> "12************34"
     * }
     * </pre>
     *
     * @param data
     * @param mask
     * @return masked string.
     */
    public static String mask(String data, String mask) {
        int markStart = -1;

        // find start mask position
        for (int i = 0; i < mask.length(); i++) {
            // if there is * in the mark
            if (mask.charAt(i) == '*') {
                // then the first position of * is the mask start position.
                markStart = i;
                break;
            }

            // Find out the fist index that is not 'x' or 'X' as the mask start position.
            if (mask.charAt(i) != 'x' && mask.charAt(i) != 'X') {
                markStart = i;
                break;
            }
        }

        // if there is no mask start index
        if (markStart == -1 || markStart >= data.length()) {
            return data;
        }

        int markEnd = markStart + 1;
        for (int i = mask.length() - 1; i > markStart + 1; i--) {
            // find out the first * index as the end mask index from the remaining mask
            // string in reverse
            if (mask.charAt(i) == '*') {
                markEnd = i + 1;
                break;
            }

            // find out the first index that is not 'x' or 'X' in reverse as the last mark
            // index
            if (mask.charAt(i) != 'x' && mask.charAt(i) != 'X') {
                markEnd = i + 1;
                break;
            }
        }

        // if you need to mask length is more then the original string
        if (mask.length() - markEnd + markStart >= data.length()) {
            return data;
        }

        // append the prefix that should not be masked.
        StringBuilder str = new StringBuilder();
        str.append(data.substring(0, markStart));

        // append *
        markEnd += data.length() - mask.length();
        for (int i = markStart; i < markEnd; i++) {
            str.append("*");
        }

        // append the suffix that should not be masked.
        if (markEnd < data.length()) {
            str.append(data.substring(markEnd));
        }

        return str.toString();
    }

    /**
     * Format a string with the given format from left.
     * <p>
     * The format pattern is a string made up by "x' or 'X'. The characters of the
     * data will replace the 'x' or 'X' in the format string in order.
     *
     * @param data   data to format.
     * @param format format patter.
     * @return string value.
     * @see #mask(String, String)
     */
    public static String format(String data, String format) {
        return format(data, format, true);
    }

    /**
     * Format a string with the given format.
     * <p>
     * The format pattern is a string made up by "x' or 'X'. The characters of the
     * data will replace the 'x' or 'X' in the format string in order.
     * <p>
     * Examples:
     * <p>
     * 
     * <pre>
     * {@code
     * String data = "1234123412341234";
     *
     * "xxxx xxxx xxxx xxxx" -> "1234 1234 1234 1234"
     * "xxxx xxxx" -> "1234 1234"
     * }
     * </pre>
     *
     * @param data     data to format.
     * @param format   format patter.
     * @param fromLeft the direction to format. is left or not.
     * @return string value.
     * @see #mask(String, String)
     */
    public static String format(String data, String format, boolean fromLeft) {
        StringBuilder result = new StringBuilder();

        if (fromLeft) {
            for (int i = 0, n = 0; i < format.length() && n < data.length(); i++) {
                char cur = format.charAt(i);

                if (cur == 'x' || cur == 'X') {
                    result.append(data.charAt(n));
                    n++;
                } else {
                    result.append(cur);
                }
            }
        } else {
            for (int i = format.length() - 1, n = data.length() - 1; i >= 0 && n >= 0; i--) {
                char cur = format.charAt(i);
                if (cur == 'x' || cur == 'X') {
                    result.insert(0, data.charAt(n));
                    n--;
                } else {
                    result.insert(0, cur);
                }
            }
        }

        return result.toString();
    }

    /**
     * Check the validity of ip.
     */
    public static boolean isIp(String ip) {
        return !(ip == null || ip.isEmpty()) && IP_PATTERN.matcher(ip).matches();
    }

    /**
     * Check the validity of port.
     */
    public static boolean isPort(String port) {
        return !(port == null || port.isEmpty()) && PORT_PATTERN.matcher(port).matches();
    }

    /**
     * Check the validity of https url.
     */
    public static boolean isHttpsUrl(String url) {
        return !(url == null || url.isEmpty()) && HTTPS_URL_PATTERN.matcher(url).matches();
    }

    /**
     * Check the validity of http url.
     */
    public static boolean isHttpUrl(String url) {
        return !(url == null || url.isEmpty()) && HTTP_URL_PATTERN.matcher(url).matches();
    }

    /**
     * Convert a string from a charset to another charset.
     * <p>
     * Just like a Chinese character "中", the correct charset is
     * {@link StandardCharsets#GBK}, so the byte values is {0xD6, 0xD0}. If we
     * {@link Strings#decode(byte[], String)} the byte array {0xD6, 0xD0} to string
     * with charset {@link StandardCharsets#ISO_8859_1}, we will get "ÖÐ". Now we
     * need to convert the charset from {@link StandardCharsets#ISO_8859_1} to
     * {@link StandardCharsets#GBK}:
     * <p>
     * 
     * <pre>
     * {@code
     *  convert("ÖÐ", StandardCharsets.ISO_8859_1, StandardCharsets.GBK) -> "中"
     * }
     * </pre>
     *
     * @param data        data to convert.
     * @param fromCharset from charset.
     * @param toCharset   to charset.
     * @return string value.
     * @see #convertCharset(String, String)
     */
    public static String convertCharset(String data, StandardCharsets.Charsets fromCharset,
                                        StandardCharsets.Charsets toCharset) {
        return decode(Strings.encode(data), toCharset);
    }

    /**
     * Convert a string from a default charset {@link StandardCharsets#GBK} to
     * another charset.
     * <p>
     * 
     * <pre>
     * {@code
     *  convert("ÖÐ", StandardCharsets.GBK) -> "中"
     * }
     * </pre>
     *
     * @param data      data to convert.
     * @param toCharset to charset.
     * @return string with the new charset.
     * @see #convertCharset(String, String, String)
     */
    public static String convertCharset(String data, StandardCharsets.Charsets toCharset) {
        return decode(Strings.encode(data, StandardCharsets.Charsets.ISO_8859_1), toCharset);
    }

    /**
     * Encode with given charset, such as "UTF-8"
     *
     * @param data        the string to be encoded.
     * @param charsetName charset name, constants in {@link StandardCharsets}.
     * @return the encoded result.
     */
    public static byte[] encode(String data, StandardCharsets.Charsets charsetName) {
        try {
            return data.getBytes(charsetName.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Encode with default charset {@link StandardCharsets#ISO_8859_1}
     *
     * @param data the string to be encoded.
     * @return the encoded result.
     */
    public static byte[] encode(String data) {
        return encode(data, StandardCharsets.Charsets.ISO_8859_1);
    }

    /**
     * Extend a normal string to a ascii string.
     * <p>
     * Examples:
     * <p>
     * <blockquote>
     * 
     * <pre>
     * "123" --> "313233"
     * </pre>
     * 
     * </blockquote>
     */
    public static String extendToHexAscii(String data) {
        return Bytes.toHexString(Strings.encode(data));
    }

    /**
     * Increase a string value.
     * <p>
     * The method use {@link Long} to convert the string, so the value should more
     * the long max value. If the original value has prefix '0', the prefix will be
     * held on.
     * <p>
     * Examples:
     * <p>
     * 
     * <pre>
     * {@code
     *  "0" -> "1"
     *  "9" -> "10"
     *  "000009s" -> "000010"
     *
     * }
     * </pre>
     *
     * @param value long value string.
     * @return increased value.
     */
    public static String increase(String value) {
        long longValue = Long.parseLong(value);

        if (longValue < 0) {
            throw new IllegalArgumentException("The long value should be positive.");
        }
        String increasedValue = String.valueOf(longValue + 1);

        if (increasedValue.length() >= value.length()) {
            return increasedValue;
        }

        return Strings.padStart(increasedValue, value.length(), '0');
    }

    /**
     * Trim a string with give character both start and end.
     *
     * @param data data to be processed.
     * @param c    character to be trimmed.
     * @return trimmed string.
     */
    public static String trim(String data, Character c) {
        int len = data.length();
        int st = 0;

        while ((st < len) && (data.charAt(st) == c)) {
            st++;
        }
        while ((st < len) && (data.charAt(len - 1) == c)) {
            len--;
        }

        return ((st > 0) || (len < data.length())) ? data.substring(st, len) : data;
    }

    /**
     * Trim a string with give default character ' ' both start and end.
     *
     * @param data data to be processed.
     * @return trimmed string.
     */
    public static String trim(String data) {
        return data.trim();
    }

    /**
     * Trim a string with give character from start.
     *
     * @param data data to be processed.
     * @param c    character to be trimmed.
     * @return trimmed string.
     */
    public static String trimStart(String data, char c) {
        int len = data.length();
        int st = 0;

        while ((st < len) && (data.charAt(st) == c)) {
            st++;
        }

        return (st > 0) ? data.substring(st, len) : data;

    }

    /**
     * Trim a string with default character ' ' from start.
     *
     * @param data data to be processed.
     * @return trimmed string.
     */
    public static String trimStart(String data) {
        return trimStart(data, ' ');
    }

    /**
     * Trim a string with give character from end.
     *
     * @param data data to be processed.
     * @param c    character to be trimmed.
     * @return trimmed string.
     */

    public static String trimEnd(String data, Character c) {
        int len = data.length();
        int st = 0;

        while ((st < len) && (data.charAt(len - 1) == c)) {
            len--;
        }

        return (len < data.length()) ? data.substring(st, len) : data;
    }

    /**
     * Trim a string with default character ' ' from end.
     *
     * @param data data to be processed.
     * @return trimmed string.
     */
    public static String trimEnd(String data) {
        return trimEnd(data, ' ');
    }

    /**
     * Extend a string with default encoding charset
     * {@link StandardCharsets#ISO_8859_1}
     * <p>
     * Examples:
     * <p>
     * <blockquote>
     * 
     * <pre>
     * "123" --> "313233"
     * </pre>
     * 
     * </blockquote>
     *
     * @param data string to extend.
     * @return extended string.
     * @see #extend(String, String)
     */
    public static String extend(String data) {
        return Bytes.toHexString(encode(data, StandardCharsets.Charsets.ISO_8859_1));
    }

    /**
     * Extend a string with default encoding charset {@link StandardCharsets#GBK}
     * <p>
     * Encode the given string with the charset to get a byte array, then convert
     * the the byte array a hex string.
     * <p>
     * Examples:
     * <p>
     * <blockquote>
     * 
     * <pre>
     * "123" --> "313233"
     * extend("中", StandardCharsets.GBK) -> "D6D0"
     * </pre>
     * 
     * </blockquote>
     *
     * @param data string to extend.
     * @return extended string.
     * @see #extend(String)
     * @see #shrink(String, String)
     */
    public static String extend(String data, StandardCharsets.Charsets charsetName) {
        return Bytes.toHexString(encode(data, charsetName));
    }

    /**
     * Shrink a hex string with default charset {@link StandardCharsets#ISO_8859_1}.
     * <p>
     * The reverse operation to {@link #extend(String, String)}.
     * <p>
     * Get a byte array from a hexString with {@link Bytes#fromHexString(String)},
     * then {@link Strings#encode(String)} the byte array to a readable string with
     * the give charset.
     *
     * @param hexString data to shrink.
     * @return shrunk string.
     * @see #extend(String, String)
     * @see #shrink(String)
     */
    public static String shrink(String hexString) {
        return shrink(hexString, StandardCharsets.Charsets.ISO_8859_1);
    }

    /**
     * Shrink a hex string.
     * <p>
     * The reverse operation to {@link #extend(String, String)}. Each 2-characters
     * will generate a byte.
     * <p>
     * Get a byte array from a hexString with {@link Bytes#fromHexString(String)},
     * then {@link Strings#encode(String)} the byte array to a readable string with
     * the give charset.
     * <p>
     * Examples:
     * <p>
     * 
     * <pre>
     * {@code
     *      shrink("313233", StandardCharsets.ISO_8859_1) -> "123"
     *      shrink("D6D0", StandardCharsets.GBK) -> "中"
     *      shrink("D6D0", StandardCharsets.ISO_8859_1) -> "ÖÐ"
     * }
     * </pre>
     *
     * @param hexString data to shrink.
     * @return shrunk string.
     * @see #extend(String, String)
     * @see #shrink(String)
     */
    public static String shrink(String hexString, StandardCharsets.Charsets charsetName) {
        return decode(Bytes.fromHexString(hexString), charsetName);
    }

    /**
     * Decode with default charset {@link StandardCharsets#ISO_8859_1}.
     *
     * @param data data to be decoded.
     * @return decoded string.
     */
    public static String decode(byte[] data) {
        return decode(data, StandardCharsets.Charsets.ISO_8859_1);
    }

    /**
     * Decode with given charset name.
     *
     * @param data        data to be decoded.
     * @param charsetName charset name, constants in {@link StandardCharsets}.
     * @return decoded string.
     */
    public static String decode(byte[] data, StandardCharsets.Charsets charsetName) {
        try {
            return new String(data, charsetName.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Make the give string's length fixed with default character '0'.
     * <p>
     * If the length > given length, then cut out the trail. If the length is <
     * given length, then the data will be padded according to the alignment.
     * <p>
     * Examples:
     * 
     * <pre>
     * {@code
     * Strings.fixLength("", 5, Bytes.ALIGN_LEFT, ' ') -> "00000"
     * Strings.fixLength("1", 5, Bytes.ALIGN_LEFT, ' ') -> "10000"
     * }
     * </pre>
     *
     * @param data        string to process.
     * @param fixedLength fixed length
     * @return the fixed length string.
     */
    public static String fixLength(String data, int fixedLength, Bytes.ALIGN align) {
        return fixLength(data, fixedLength, align, '0');
    }

    /**
     * Make the give string's length fixed.
     * <p>
     * If the length > given length, then cut out the trail. If the length is <
     * given length, then the data will be padded according to the alignment.
     * <p>
     * Examples:
     * 
     * <pre>
     * {@code
     * Strings.fixLength("", 5, Bytes.ALIGN_LEFT, ' ') -> "     "
     * Strings.fixLength("1", 5, Bytes.ALIGN_LEFT, ' ') -> "1    "
     * Strings.fixLength("99", 4, Bytes.ALIGN_RIGHT, '*') > "**99"
     * }
     * </pre>
     *
     * @param data        string to process.
     * @param fixedLength fixed length
     * @param padding     padding character
     * @return the fixed length string.
     */
    public static String fixLength(String data, int fixedLength, Bytes.ALIGN align, char padding) {
        int length = data.length();
        if (length == fixedLength) {
            return data;
        } else if (length > fixedLength) {
            // the length is more then fixed length cut out
            return data.substring(0, fixedLength);
        } else if (align == Bytes.ALIGN.ALIGN_LEFT) {
            // the length is < fixed length
            // and align is left
            return padEnd(data, fixedLength, padding);
        } else {
            // the length is < fixed length
            // and align is right
            return padStart(data, fixedLength, padding);
        }
    }

    /**
     * Cut out the string tail if the length is more then the given max length.
     *
     * @param data the source string
     * @param max  the max length of number
     * @return the destination string
     */
    public static String cutTail(String data, int max) {
        return data.length() <= max ? data : data.substring(0, max);
    }
}