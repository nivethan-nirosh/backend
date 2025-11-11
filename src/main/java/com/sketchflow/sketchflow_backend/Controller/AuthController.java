package com.sketchflow.sketchflow_backend.Controller;

import com.sketchflow.sketchflow_backend.Config.JwtUtil;
import com.sketchflow.sketchflow_backend.Model.User;
import com.sketchflow.sketchflow_backend.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth") // Base URL for this controller
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {

        // 1. Check if user already exists
        if (userRepository.findByUsername(request.username()).isPresent()) {
            return ResponseEntity.badRequest().body(null); // Or some error message
        }

        // 2. Create new user
        User user = new User();
        user.setUsername(request.username());
        // 3. IMPORTANT: Hash the password before saving!
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setEmail(request.email());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());

        userRepository.save(user);

        // 4. Generate a JWT token for the new user
        String token = jwtUtil.generateToken(user);

        // 5. Return the token
        return ResponseEntity.ok(new AuthResponse(token));
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {

        // 1. Authenticate the user using Spring Security's AuthenticationManager
        // This will check the username and hashed password
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        // 2. If authentication is successful, load the user
        // (We know the user exists, or else the line above would have thrown an exception)
        var user = userRepository.findByUsername(request.username())
                .orElseThrow(); // Should not happen

        // 3. Generate a JWT token
        String token = jwtUtil.generateToken(user);

        // 4. Return the token
        return ResponseEntity.ok(new AuthResponse(token));
    }
    @GetMapping("/hello")
    public String hello() {
        // This line gets the user principal that our JwtAuthFilter set
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        return "Hello, " + auth.getName() + "! Your token works.";
    }
}
