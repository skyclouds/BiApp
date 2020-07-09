package com.biapp.key;

/**
 * Defines whether the protected key may be
 * transferred outside the cryptographic domain in
 * which the key is found.
 *
 * <p> 定义受保护的密钥是否可以传输到加密设备之外
 *
 * @author Yun
 */
public interface Exportability {

    /**
     * Exportable under a DAK in a form meeting the requirements of X9.24 Parts 1 or 2.
     *
     * <p> 以 DAK 加密形式导出
     */
    byte EXPORTABLE_UNDER_KEK = 'E';

    /**
     * Non-exportable
     *
     * <p> 不可导出
     */
    byte NON_EXPORTABLE = 'N';

    /**
     * Sensitive, Exportable under a DAK in a form not necessarily meeting the requirements of X9.24 Parts 1 or 2..
     *
     * <p> 敏感的，不一定以 DAK 加密形式导出
     */
    byte SENSITIVE = 'S';

}
