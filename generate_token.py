"""
generate_token.py
-----------------
Generates a test JWT token for the Secure API Gateway.
Run: python generate_token.py
"""

import base64
import hmac
import hashlib
import json
import time
import struct

SECRET_KEY = "MySuperSecretKey_ChangeThisInProduction_2024!"
ISSUER     = "SecureAPIGateway"
AUDIENCE   = "SecureAPIGateway-Clients"

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def create_jwt(secret: str, issuer: str, audience: str, expires_in_seconds: int = 3600) -> str:
    now = int(time.time())

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "test-user-001",
        "name": "Gateway Test User",
        "iat": now,
        "exp": now + expires_in_seconds,
    }

    header_b64  = base64url_encode(json.dumps(header,  separators=(",", ":")).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"

if __name__ == "__main__":
    token = create_jwt(SECRET_KEY, ISSUER, AUDIENCE)
    print("\n=== Secure API Gateway — Test JWT Token ===")
    print(f"\nToken (valid 1 hour):\n{token}")
    print("\nUse this in Swagger UI → Authorize → paste the token.")
    print('Or: curl -H "Authorization: Bearer <token>" http://localhost:5000/api/gateway\n')
