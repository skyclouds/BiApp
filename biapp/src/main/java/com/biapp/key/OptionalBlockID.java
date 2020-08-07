package com.biapp.key;

/**
 * @author yun
 */
public interface OptionalBlockID {
    /**
     * Asymmetric public key certificate; see format definition below.
     */
    String CT = "CT";
    /**
     * Hash algorithm for HMAC
     */
    String HM = "HM";
    /**
     * Initial Key Identifier for the Initial DUKPT Key. Similar to the ‘KS’ block,
     * the Initial Key ID is the concatenation of the BDK ID and the Derivation
     * ID encoded in hex-ASCII. For AES DUKPT it is 16 hex-ASCII
     * characters in length. This value is used to instantiate the use of the
     * Initial DUKPT key on the receiving device and it identifies the Initial
     * Key derived from a BDK. (See ANS X9.24 part 3 Annex B for
     * examples.)
     */
    String IK = "IK";
    /**
     * Key Check Value of wrapped key; computed according to X9.24-1-
     * 2017 Annex A not used as an integrity mechanism.
     */
    String KC = "KC";
    /**
     * Key Check Value of KBPK; computed according to X9.24-1-
     * 2017Annex A. not used as an integrity mechanism.
     */
    String KP = "KP";
    /**
     * Key Set Identifier, encoded in hex-ASCII; optionally used to identify the
     * key within a system. (See ANS X9.24 part 3 for examples.)
     */
    String KS = "KS";

    /**
     * Key Block Values: Informational field indicating the version of the key
     * block field values. Sub-fields are defined in Error! Reference source
     * not found.
     */
    String KV="KV";

    /**
     * A variable-length padding field used as the last Optional Block. The
     * padding block is used to bring the total length of all Optional Blocks in
     * the key block to a multiple of the encryption block length. The data
     * bytes in this block are filled with readable ASCII characters.
     */
    String PB="PB";

    /**
     * Time Stamp; the time and date (in UTC Time format) that indicates
     * when the key block was formed.
     */
    String TS="TS";
}
