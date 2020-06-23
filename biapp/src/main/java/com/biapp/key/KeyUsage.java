package com.biapp.key;


/**
 * Identifies the key usage
 * <p>
 * Provides information about the intended
 * function of the protected key/sensitive data.
 * Common functions include encrypting data,
 * encrypting PINs, and calculating a MAC.
 *
 * @author Yun
 */
public interface KeyUsage {
    

    /**
     * BDK Base Derivation Key
     * ‘X’
     */
    String BDK = "B0";

    /**
     * Initial DUKPT Key
     * ‘X’
     */
    String DUKPT_INIT_KEY = "B1";

    /**
     * Base Key Variant Key
     * ‘Y’
     */
    String BASE_KEY_VARIANT_KEY = "B2";
    /**
     * CVK Card Verification Key
     * ‘C’, ‘G’, ‘V’
     */
    String CVK = "C0";

    /**
     * Symmetric Key for Data Encryption
     * ‘B’, ‘D’, ‘E’
     */
    String SYMMETRIC_KEY_DATA_ENCRYPTION = "D0";

    /**
     * Asymmetric Key for Data Encryption
     * ‘B’, ‘D’, ‘E’
     */
    String ASYMMETRIC_KEY_DATA_ENCRYPTION = "D1";

    /**
     * Data Encryption Key for Decimalization Table
     * ‘B’, ‘D’, ‘E’
     */
    String DECIMALIZATION_TABLE_DATA_ENCRYPTION = "D2";

    /**
     * EMV/chip Issuer Master Key: Application cryptograms
     * ‘X’
     */
    String APPLICATION_CRYPTOGRAMS = "E0";

    /**
     * EMV/chip Issuer Master Key: Secure Messaging for Confidentiality
     * ‘X’
     */
    String MESSAGING_FOR_CONFIDENTIALITY = "E1";

    /**
     * EMV/chip Issuer Master Key:  Secure Messaging for Integrity
     * ‘X’
     */
    String MESSAGING_FOR_INTEGRITY = "E2";

    /**
     * EMV/chip Issuer Master Key: Data Authentication Code
     * ‘X’
     */
    String DATA_AUTHENTICATION_CODE = "E3";

    /**
     * EMV/chip Issuer Master Key: Dynamic Numbers
     * ‘X’
     */
    String DYNAMIC_NUMBERS = "E4";

    /**
     * EMV/chip Issuer Master Key: Card Personalization
     * ‘X’
     */
    String CARD_PERSONALIZATION = "E5";
    /**
     * EMV/chip Issuer Master Key: Other
     * ‘X’
     */
    String OTHER = "E6";

    /**
     * Initialization Vector (IV)
     * ‘N’
     */
    String IV = "I0";

    /**
     * Key Encryption or wrapping
     * ‘B’, ‘D’, ‘E’
     */
    String KEY_ENC_OR_WRAP = "K0";

    /**
     * TR-31 Key Block Protection Key
     * ‘B’, ‘D’, ‘E’
     */
    String TR31_PROTECTION_KEY = "K1";

    /**
     * TR-34 Asymmetric key
     * ‘B’, ‘D’, ‘E’
     */
    String TR34_ASYMMETRIC_KEY = "K2";

    /**
     * Asymmetric key for key agreement/key wrapping
     * ‘B’, ‘D’, ‘E’, ‘X’
     */
    String ASYMMETRIC_KEY_AGREE_WRAP = "K3";

    /**
     * ISO_16609_MAC_algorithm_1
     * ‘C’, ‘G’, ‘V’
     */
    String ISO_16609_MAC_ALGORITHM_1 = "M0";

    /**
     * ISO 9797-1 MAC Algorithm 1
     * ‘C’, ‘G’, ‘V’
     */
    String ISO_9797_1_MAC_Algorithm_1 = "M1";

    /**
     * ISO 9797-1 MAC Algorithm 2
     * ‘C’, ‘G’, ‘V’
     */
    String ISO_9797_1_MAC_Algorithm_2 = "M2";

    /**
     * ISO 9797-1 MAC Algorithm 3
     * ‘C’, ‘G’, ‘V’
     */
    String ISO_9797_1_MAC_Algorithm_3 = "M3";

    /**
     * ISO 9797-1 MAC Algorithm 4
     * ‘C’, ‘G’, ‘V’
     */
    String ISO_9797_1_MAC_Algorithm_4 = "M4";

    /**
     * ISO 9797-1:1999 MAC Algorithm 5
     * ‘C’, ‘G’, ‘V’
     */
    String ISO_9797_1_1999_MAC_ALGORITHM_5 = "M5";

    /**
     * ISO 9797-1:2011 MAC Algorithm 5/CMAC
     * ‘C’, ‘G’, ‘V’
     */
    String CMAC = "M6";

    /**
     * HMAC
     * ‘C’, ‘G’, ‘V’
     */
    String HMAC = "M7";

    /**
     * ISO 9797-1:2011 MAC Algorithm 6
     * ‘C’, ‘G’, ‘V’
     */
    String ISO_9797_1_2011_MAC_ALGORITHM_6 = "M8";

    /**
     * PIN Encryption
     * ‘B’, ’D’, ‘E’
     */
    String PIN_ENCRYPTION = "P0";

    /**
     * Asymmetric key pair for digital signature
     * ‘S’, ‘V’
     */
    String ASYMMETRIC_KEY_SIGNATURE = "S0";

    /**
     * 自定义日志签名
     * ‘S’
     */
    String LOG_SIGNATURE = "50";

    /**
     * Asymmetric key pair, CA key
     * ‘S’, ‘V’
     */
    String CA = "S1";

    /**
     * Asymmetric key pair, nonX9.24 key
     * ‘S’, ‘V’, ‘T’, ‘B’, ‘D’, ‘E’
     */
    String NONX9_24 = "S2";

    /**
     * PIN verification, KPV, other algorithm
     * ‘C’, ‘G’, ‘V’
     */
    String KPV = "V0";

    /**
     * PIN verification, IBM 3624
     * ‘C’, ‘G’, ‘V’
     */
    String IBM_3624 = "V1";

    /**
     * PIN Verification, VISA PVV
     * ‘C’, ‘G’, ‘V’
     */
    String VISA_PVV = "V2";
    /**
     * PIN Verification, X9.132 algorithm 1
     * ‘C’, ‘G’, ‘V’
     */
    String X9_132_ALGORITHM_1 = "V3";
    /**
     * PIN Verification, X9.132 algorithm 2
     * ‘C’, ‘G’, ‘V’
     */
    String X9_132_ALGORITHM_2 = "V4";
}
