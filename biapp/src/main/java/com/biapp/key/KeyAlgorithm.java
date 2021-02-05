package com.biapp.key;

/**
 * Defines key block encryption algorithm
 *
 * @author Yun
 */
public interface KeyAlgorithm {
    byte AES = 'A';
    byte DEA = 'D';
    byte ELLIPTIC_CURVE = 'E';
    byte HMAC_SHA_1 = 'H';
    byte HMAC_SHA_2 = 'I';
    byte HMAC_SHA_3 = 'J';
    byte RSA = 'R';
    byte DSA = 'S';
    byte TDEA = 'T';
}
