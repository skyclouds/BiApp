package com.biapp.key;

/**
 * @author yun
 */
public interface VerNum {
    /**
     * Key versioning is not used for this key
     */
    String NONE="00";
    /**
     * The value carried in this key block is a component of a key. Local rules
     * will dictate the proper use of a component. Typically, a key with a
     * specific header will be derived from two or more components with the
     * same header (with the obvious exception of the key version bytes).
     */
    String KEY_COMPONENTT="c0";
}
