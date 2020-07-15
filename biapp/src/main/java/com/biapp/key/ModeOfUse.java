package com.biapp.key;

/**
 * Defines the operation the protected key can
 * perform. For example, a MAC key may be
 * limited to verify-only.
 *
 * @author Yun
 */
public interface ModeOfUse {
    /**
     * Both Encrypt & Decrypt / Wrap &Unwrap. "KUM" : Key Use Mode.
     */
    byte ENC_DEC_WRAP_UNWRAP = 'B';
    /**
     * Both Generate & Verify : 主要针对 MAC : 生成 MAC or 校验 MAC.
     */
    byte GENERATE_AND_VERIFY = 'C';
    /**
     * Decrypt / Unwrap Only : 只能用来解密, 比如 MK.
     */
    byte DEC_OR_UNWRAP_ONLY = 'D';

    /**
     * Encrypt / Wrap Only : 只能用在加密, 比如 PIN key.
     */
    byte ENC_OR_WRAP_ONLY = 'E';

    /**
     * Generate Only : 只能用来生成 MAC.
     */
    byte GENERATE_ONLY = 'G';

    /**
     * No special restrictions (other than restrictions implied by the Key Usage)
     */
    byte NO_RESTRICTIONS = 'N';

    /**
     * Signature Only
     */
    byte SIGNATURE_ONLY = 'S';

    /**
     * Verify Only : 只能用来校验 MAC, 内部计算的 MAC 结果不能导出.
     */
    byte VERIFY_ONLY = 'V';

    /**
     * Key used to derive other key(s) : 可以是 DUKPT init key 的 属性.
     */
    byte DERIVE_KEYS = 'X';

    /***
     * Both Sign & Decrypt
     */
    byte SIGN_AND_DEC = 'T';

    /**
     * Key used to create key variants
     */
    byte CREATE_KEY_VARIANTS = 'Y';
}
