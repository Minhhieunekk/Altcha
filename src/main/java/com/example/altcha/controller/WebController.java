package com.example.altcha.controller;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.altcha.altcha.Altcha;
import org.altcha.altcha.Altcha.Algorithm;
import org.altcha.altcha.Altcha.Challenge;
import org.altcha.altcha.Altcha.ChallengeOptions;
import org.altcha.altcha.Altcha.Solution;
import org.springframework.web.bind.annotation.*;



@RestController
@RequestMapping("/")
@Slf4j
public class WebController {

  // Default value if env variable is not set
  private final String hmacKey = "2211"; // Thay bằng key thực tế của bạn
    private static final Algorithm DEFAULT_ALGORITHM = Algorithm.SHA256;
    private static final long DEFAULT_MAX_NUMBER = 1000000L;

    @GetMapping("/")
    public String showForm() {
        return "index"; // Render index.html
    }

    @GetMapping("/altcha")
    @CrossOrigin(origins = "*")
    public Challenge altcha() {
        try {
            ChallengeOptions options = new ChallengeOptions();
            options.algorithm = DEFAULT_ALGORITHM; // Sử dụng SHA256 như mặc định
            options.hmacKey = hmacKey;
            options.maxNumber = DEFAULT_MAX_NUMBER; // Giới hạn tối đa

            log.info("Generating challenge with HMAC key: " + options.hmacKey);
            return Altcha.createChallenge(options);
        } catch (Exception e) {
            log.error("Error generating challenge", e);
            throw new RuntimeException("Error generating challenge", e);
        }
    }

    @PostMapping("/solve_challenge")
    @CrossOrigin(origins = "*")
    public Map<String, Object> solveChallenge(@RequestParam String challenge, @RequestParam String salt) {
        Map<String, Object> response = new HashMap<>();
        try {
            Algorithm algorithm = DEFAULT_ALGORITHM; // Sử dụng SHA256
            long maxNumber = DEFAULT_MAX_NUMBER; // Giới hạn tối đa
            long start = 0L; // Bắt đầu từ 0

            // Giải challenge
            Solution solution = Altcha.solveChallenge(challenge, salt, algorithm, maxNumber, start);
            if (solution == null) {
                response.put("success", false);
                response.put("error", "No valid solution found within the max number limit");
                return response;
            }

            // Tạo payload cho client
            Map<String, Object> payloadData = new HashMap<>();
            payloadData.put("algorithm", algorithm.getName());
            payloadData.put("challenge", challenge);
            payloadData.put("number", solution.number);
            payloadData.put("salt", salt);

            // Tạo signature dựa trên challenge string
            String challengeStr = challenge; // Sử dụng trực tiếp challenge đã cho
            String signature = Altcha.hmacHex(algorithm, challengeStr.getBytes(StandardCharsets.UTF_8), hmacKey);
            payloadData.put("signature", signature);

            // Chuyển thành Base64
            String jsonPayload = new ObjectMapper().writeValueAsString(payloadData);
            String base64Payload = Base64.getEncoder().encodeToString(jsonPayload.getBytes(StandardCharsets.UTF_8));

            response.put("success", true);
            response.put("base64Payload", base64Payload);
            response.put("took", solution.took); // Thời gian giải (tuỳ chọn)
        } catch (Exception e) {
            log.error("Error solving challenge", e);
            response.put("success", false);
            response.put("error", "Error solving challenge: " + e.getMessage());
        }
        return response;
    }

    @PostMapping("/submit")
    @CrossOrigin(origins = "*")
    public Map<String, Object> submit(@RequestParam Map<String, String> formData) {
        Map<String, Object> response = new HashMap<>();
        try {
            String payload = formData.get("altcha");
            if (payload == null) {
                response.put("success", false);
                response.put("error", "'altcha' field is missing");
                return response;
            }

            log.info("Verifying payload: " + payload);
            boolean isValid = Altcha.verifySolution(payload, hmacKey, true); // Kiểm tra expires

            if (!isValid) {
                response.put("success", false);
                response.put("error", "Invalid ALTCHA solution");
                return response;
            }

            response.put("success", true);
            response.put("data", formData);
        } catch (Exception e) {
            log.error("Error verifying solution", e);
            response.put("success", false);
            response.put("error", "Error verifying solution: " + e.getMessage());
        }
        return response;
    }
// luồng phức tạp này chưa giải quyết được
    @PostMapping("/submit_spam_filter")
    @CrossOrigin(origins = "*")
    public Map<String, Object> submitSpamFilter(@RequestParam Map<String, String> formData) {
        Map<String, Object> response = new HashMap<>();
        try {
            String payload = formData.get("altcha");

            Altcha.ServerSignatureVerification verification;

            verification = Altcha.verifyServerSignature(payload, hmacKey);

            response.put("success", verification.verified);
            response.put("data", formData);
            response.put("verificationData", verification.verificationData);
        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("error", "Error verifying server signature: " + e.getMessage());
        }
        return response;
    }
}
