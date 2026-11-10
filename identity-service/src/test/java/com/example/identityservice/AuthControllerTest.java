package com.example.identityservice;

import com.example.identityservice.entity.User;
import com.example.identityservice.repository.UserRepository;
import com.example.identityservice.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${jwt-secret:${jwt.jwt-secret}}")
    private String secret;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void register_shouldReturnCreatedUserWithoutPassword_andSaveHashedPasswordInDb() throws Exception {
        String requestJson = """
            {
                "username": "john_doe",
                "password": "mySecurePassword123",
                "role": "USER"
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.username").value("john_doe"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist());

        User savedUser = userRepository.findByUsername("john_doe").orElseThrow();
        assertThat(savedUser.getPassword()).isNotEqualTo("mySecurePassword123");
        assertThat(savedUser.getPassword()).startsWith("$2a$");
        assertThat(passwordEncoder.matches("mySecurePassword123", savedUser.getPassword())).isTrue();
    }

    @Test
    void testToken_shouldReturnValidJwtWithSubAndRole() throws Exception {
        User user = new User("alice", passwordEncoder.encode("secret"), "ADMIN");
        userRepository.save(user);

        MvcResult result = mockMvc.perform(get("/api/auth/test-token").param("username", "alice"))
                .andExpect(status().isOk())
                .andReturn();

        String token = result.getResponse().getContentAsString();
        assertThat(token).isNotEmpty();

        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(secret);
        } catch (Exception e) {
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        }
        if (keyBytes.length < 32) {
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        }
        Key signingKey = Keys.hmacShaKeyFor(keyBytes);

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.get("role", String.class)).isEqualTo("ADMIN");
    }

    @Test
    void testToken_whenUserNotFound_shouldReturn404() throws Exception {
        mockMvc.perform(get("/api/auth/test-token").param("username", "non_existing_user"))
                .andExpect(status().isNotFound());
    }

    @Test
    void login_withCorrectCredentials_shouldReturn200AndValidToken_withoutHttpSession() throws Exception {
        User user = new User("testuser", passwordEncoder.encode("password123"), "USER");
        userRepository.save(user);

        String loginJson = """
            {
                "username": "testuser",
                "password": "password123"
            }
            """;

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();

        // Verify no HTTP session created (stateless)
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    void login_withWrongPassword_shouldReturn401BadCredentials() throws Exception {
        User user = new User("testuser", passwordEncoder.encode("password123"), "USER");
        userRepository.save(user);

        String loginJson = """
            {
                "username": "testuser",
                "password": "wrongPassword"
            }
            """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Bad credentials"));
    }

    @Test
    void login_withNonExistentUser_shouldReturn401BadCredentials() throws Exception {
        String loginJson = """
            {
                "username": "unknown_user",
                "password": "password123"
            }
            """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Bad credentials"));
    }
}
