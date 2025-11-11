package com.sketchflow.sketchflow_backend.Controller;

// A record to hold registration data
public record RegisterRequest(String username, String password, String email, String firstName, String lastName) {}
