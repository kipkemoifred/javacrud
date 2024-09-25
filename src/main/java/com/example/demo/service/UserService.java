package com.example.demo.service;

import com.example.demo.entity.RegisterRequest;
import com.example.demo.entity.Users;
import com.example.demo.repository.UsersRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UsersRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void registerUser(RegisterRequest registerRequest) throws Exception {
        // Check if the user already exists
        if (userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            throw new Exception("Username already exists");
        }

        // Create a new user with the hashed password
        Users user = new Users();
        user.setUsername(registerRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword())); // Encode the password
//        user.setRoles(registerRequest.getRole() != null ? registerRequest.getRole() : "USER");  // Default role if not provided

        userRepository.save(user);  // Save the user to the database
    }
}

