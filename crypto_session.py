from __future__ import annotations
import base64
import datetime
import hashlib
import ipaddress
import os
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

UNIFIED_SECRET_KEY = os.environ.get(
    "SECRET_KEY", "CourseSecurityProject-Unified-Secret-Key-2026"
)

class SessionCryptoManager:

    def __init__(self, secret_key: str = UNIFIED_SECRET_KEY, certs_dir: str = "certs"):
        self.secret_key = secret_key

        fernet_key = base64.urlsafe_b64encode(
            hashlib.sha256(self.secret_key.encode("utf-8")).digest()
        )
        self.cipher = Fernet(fernet_key)
        self.certs_dir = certs_dir
        self.cert_path = os.path.join(self.certs_dir, "cert.pem")
        self.key_path = os.path.join(self.certs_dir, "key.pem")

    def apply_flask_session_config(self, app, cookie_name: str = "session", samesite: str = "Lax"):
        app.secret_key = self.secret_key
        app.config["SESSION_COOKIE_NAME"] = cookie_name
        app.config["SESSION_COOKIE_HTTPONLY"] = True
        app.config["SESSION_COOKIE_SAMESITE"] = samesite
        app.config["SESSION_COOKIE_SECURE"] = True

    def encrypt_value(self, value: str) -> str:
        return self.cipher.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt_value(self, encrypted_value: str | None) -> str | None:
        if not encrypted_value:
            return None
        try:
            return self.cipher.decrypt(encrypted_value.encode("utf-8")).decode("utf-8")
        except Exception:
            return None

    def ensure_self_signed_cert(self, common_name: str = "localhost") -> tuple[str, str]:
        os.makedirs(self.certs_dir, exist_ok=True)
        if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            return self.cert_path, self.key_path

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "SA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CourseSecurityProject"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(common_name),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        with open(self.key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        with open(self.cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        return self.cert_path, self.key_path