package com.biapp;

/**
 * BIAppException
 *
 * @author yun
 */
public class BIAppException extends Exception {

    /**
     * Error code.
     */
    private int errorCode = -1;

    public BIAppException() {
    }

    public BIAppException(int errorCode) {
        this.errorCode = errorCode;
    }

    public BIAppException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public BIAppException(String message) {
        super(message);
    }

    public BIAppException(String message, Throwable cause) {
        super(message, cause);
    }

    public BIAppException(Throwable cause) {
        super(cause.getMessage(), cause);
    }

    /**
     * Get error code.
     *
     * @return Error code.
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * Set error code.
     *
     * @param errorCode Error code.
     */
    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }
}
