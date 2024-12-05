package com.matheusdev.login_auth_api.infra.security;

import org.springframework.stereotype.Service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;

@Service
public class PasswordService {
    private static final Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);

    public String hashPassword(String password) {
        return argon2.hash(1, 47104, 1, password.toCharArray());
    }

    public boolean verifyPassword(String hash, String password) {
        return argon2.verify(hash, password.toCharArray());
    }
}
