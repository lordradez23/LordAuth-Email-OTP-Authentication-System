package com.lordradeez.services;

/**
 * Result of a login attempt — gives controllers precise context
 * to render the correct error page or message.
 */
public enum LoginResult {
    /** Credentials valid, OTP sent. */
    OTP_SENT,
    /** Email or password incorrect. */
    INVALID_CREDENTIALS,
    /** Account is temporarily locked due to too many failed attempts. */
    ACCOUNT_LOCKED
}
