# Adaptive Multi-Factor Authentication (MFA) & Session Hardening Engine

A resilient identity and access management service built with Python and Flask. The system implements multi-layered defensive authentication, combining RFC 6238 TOTP-based two-factor authentication, adaptive brute-force mitigations (IP rate limiting, dynamic CAPTCHA challenges, and progressive account lockouts), session fixation prevention, and contextual security auditing.

---

## Authentication Lifecycle & Threat Mitigation Architecture

```text
                                [ User HTTP POST: Login ]
                                           │
                                           ▼
                     [ Layer 1: Sliding Window IP Rate Limiter ]
                          (Max 7 attempts / min per remote IP)
                                           │
                                           ├─► Exceeded ──► [ HTTP 429 / Rejection Log ]
                                           ▼
                        [ Layer 2: Lockout State Check ]
                 (Enforce 5-minute lock if failed attempts >= 5)
                                           │
                                           ├─► Locked ───► [ Flash Retry Timer + WARN Log ]
                                           ▼
                      [ Layer 3: Dynamic Human Verification ]
                  (Evaluate failed attempts: if >= 3, enforce CAPTCHA)
                                           │
                                           ├─► CAPTCHA Failed ──► [ Increment & Re-render ]
                                           ▼
                     [ Layer 4: Cryptographic Verification ]
                            (Bcrypt password check)
                                           │
                  ┌────────────────────────┴────────────────────────┐
                  ▼                                                 ▼
             [ Failure ]                                       [ Success ]
       Increment Failed Counter                               Reset Counter
      Log WARNING + Client IP                           Regenerate Session ID
                                                                    │
                                                                    ▼
                                                    [ Layer 5: TOTP Verification ]
                                                    (pyotp RFC 6238 Time-Based OTP)
                                                                    │
                                                ┌───────────────────┴───────────────────┐
                                                ▼                                       ▼
                                       [ First-Time User ]                     [ Returning User ]
                                      Render QR Code Provisioning             Validate 6-digit TOTP
                                                │                                       │
                                                └───────────────────┬───────────────────┘
                                                                    ▼
                                                        [ Session Established ]
                                                    (Secure, HttpOnly, SameSite)
                                                                    │
                                                                    ▼
                                                        [ Redirect to Dashboard ]