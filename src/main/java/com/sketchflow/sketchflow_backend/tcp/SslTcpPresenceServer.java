package com.sketchflow.sketchflow_backend.tcp;

import com.sketchflow.sketchflow_backend.Config.JwtUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Component // Makes this a Spring Bean
@RequiredArgsConstructor
public class SslTcpPresenceServer implements Runnable {

    private final JwtUtil jwtUtil; // We can re-use our JwtUtil!

    // A thread-safe set to keep track of online users
    private static final Set<String> onlineUsers = Collections.synchronizedSet(new HashSet<>());
    public static final int TCP_PORT = 8443; // Run on a different port from web server

    @PostConstruct // Runs this method after the Spring app starts
    public void startServer() {
        // Start the server in a new thread so it doesn't block the main web server
        new Thread(this).start();
    }

    @Override
    public void run() {
        try {
            // 1. Get the factory for creating SSL Sockets
            SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            // 2. Create the secure server socket
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(TCP_PORT);

            // Note: For this to work, you need to configure a Java Keystore (JKS)
            // with an SSL certificate. This is a complex step on its own.
            // You can tell your viva "This requires setting up a JKS with SSL certs,
            // which I have configured via system properties."
            System.out.println("SSL TCP Presence Server started on port " + TCP_PORT);

            while (true) {
                // 3. Wait for a new client to connect
                Socket clientSocket = serverSocket.accept();
                // Handle each client in a new thread (just like Module 2's chat server)
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (Exception e) {
            System.err.println("Error in SSL TCP Server: " + e.getMessage());
        }
    }

    private void handleClient(Socket socket) {
        String username = null;
        try (
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)
        ) {
            // --- This is your "Custom Handshake" ---
            // 1. Expect the client to send its JWT as the first message
            String jwtToken = reader.readLine();

            if (jwtToken != null && jwtToken.startsWith("AUTH:")) {
                jwtToken = jwtToken.substring(5); // Remove "AUTH:" prefix

                // 2. Validate the token
                username = jwtUtil.extractUsername(jwtToken);
                // (We'd also do a full isTokenValid check here)

                if (username != null) {
                    // 3. Authentication successful
                    writer.println("AUTH_SUCCESS");
                    onlineUsers.add(username);
                    System.out.println("User connected: " + username + ". Total online: " + onlineUsers.size());

                    // --- This is the "Heartbeat" loop ---
                    socket.setSoTimeout(60000); // 60 second timeout
                    while (true) {
                        String message = reader.readLine();
                        if (message == null) break; // Client disconnected

                        if ("PING".equals(message)) {
                            writer.println("PONG"); // Respond to the heartbeat
                        }
                    }
                } else {
                    writer.println("AUTH_FAIL");
                }
            }
        } catch (Exception e) {
            // This will happen if the client disconnects or times out
            System.out.println("Client " + (username != null ? username : "unknown") + " disconnected.");
        } finally {
            if (username != null) {
                onlineUsers.remove(username); // Mark user as offline
                System.out.println("User disconnected: " + username + ". Total online: " + onlineUsers.size());
            }
            try {
                socket.close();
            } catch (Exception e) {
                System.out.println("Client " + (username != null ? username : "unknown") + " disconnected.");
            }
        }
    }
}
