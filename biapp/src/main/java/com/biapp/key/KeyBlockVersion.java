package com.biapp.key;

/**
 * Identifies the version of the key block, which
 * defines the method by which it is
 * cryptographically protected and the content and
 * layout of the block.
 *
 * @author Yun
 */
public interface KeyBlockVersion {

    /**
     * ‘A’ (0x41) – Key block protected using the
     * TDEA Key Derivation Binding Method (see
     * section 5.3.2.1)
     */
    byte A = 0x41;

    /**
     * ‘B’ (0x42) – Key block protected using the
     * TDEA Key Derivation Binding Method (see
     * section 5.3.2.1)
     */
    byte B = 0x42;

    /**
     * ‘C’ (0x43) – Key block protected using the
     * TDEA Key Derivation Binding Method (see
     * section 5.3.2.1)
     */
    byte C = 0x43;

    /**
     * ‘D’ (0x44) - Key block protected using the AES
     * Key Derivation Binding Method (see section
     * 5.3.2.3)
     */
    byte D = 0x44;
}
