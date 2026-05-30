package com.lordradeez.exception;

import org.springframework.http.HttpStatus;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Global exception handler for the MVC layer.
 * Catches unhandled runtime exceptions and renders a styled error page
 * instead of exposing stack traces to the user.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleGenericException(Exception ex, Model model) {
        model.addAttribute("errorMessage", sanitize(ex.getMessage()));
        model.addAttribute("errorType", ex.getClass().getSimpleName());
        return "error";
    }

    /** Strip any sensitive path or stack info from the message. */
    private String sanitize(String msg) {
        if (msg == null) return "An unexpected error occurred.";
        // Never expose full file paths or connection strings
        return msg.length() > 120 ? msg.substring(0, 120) + "…" : msg;
    }
}
