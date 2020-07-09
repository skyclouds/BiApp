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
    byte HMAC = 'H';
    byte RSA = 'R';
    byte DSA = 'S';
    byte TDEA = 'T';
}
