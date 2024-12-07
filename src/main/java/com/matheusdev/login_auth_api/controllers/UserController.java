package com.matheusdev.login_auth_api.controllers;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.matheusdev.login_auth_api.domain.user.User;
import com.matheusdev.login_auth_api.dto.LoginRequestDTO;
import com.matheusdev.login_auth_api.dto.RegisterRequestDTO;
import com.matheusdev.login_auth_api.dto.ResponseDTO;
import com.matheusdev.login_auth_api.infra.security.PasswordService;
import com.matheusdev.login_auth_api.repositories.UserRepository;

@RestController
@RequestMapping("/user")
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST})
public class UserController {
    private final UserRepository repository;
    private final PasswordService passwordService;

    public UserController(UserRepository repository, PasswordService passwordService) {
        this.repository = repository;
        this.passwordService = passwordService;
    }

    @GetMapping
    public ResponseEntity<String> getUser() {
        return ResponseEntity.ok("User");
    }

    @SuppressWarnings("rawtypes")
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body) {
        User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found"));
        if(passwordService.verifyPassword(user.getPassword(), body.password())) {
            return ResponseEntity.ok(new ResponseDTO(user.getName()));
        }
        return ResponseEntity.badRequest().build();
    }

    @SuppressWarnings("rawtypes")
    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body) {
        Optional<User> user = this.repository.findByEmail(body.email());
        if(user.isEmpty()) {
            User newUser = new User();
            newUser.setPassword(passwordService.hashPassword(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.repository.save(newUser);

            return ResponseEntity.ok(new ResponseDTO(newUser.getName()));
        }
        return ResponseEntity.badRequest().build();
    }
}
