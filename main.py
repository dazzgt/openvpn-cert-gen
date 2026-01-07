#!/usr/bin/env python3
import hashlib
import hmac
import os
import argparse
import base64
import struct
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timedelta, timezone

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters
from cryptography.x509.oid import NameOID


@dataclass
class CertPairDto:
    key: rsa.RSAPrivateKey
    cert: x509.Certificate


class VpnConfigGenerator:
    # Key sizes in bytes
    SERVER_KEY_SIZE = 128  # 1024 bits
    CLIENT_KEY_SIZE = 256  # 2048 bits
    AES_KEY_SIZE = 32  # 256 bits
    HMAC_KEY_SIZE = 32  # 256 bits
    TAG_SIZE = 32  # 256 bits

    # Metadata types
    METADATA_TYPE_USER = 0x00
    METADATA_TYPE_TIMESTAMP = 0x01
    metadata = None

    def __init__(self, server_seed: str | None = None, client_seed: str | None = None, secrets_dir: str = "secrets"):
        self.file_dir = Path(__file__).parent
        self.secrets_dir = self.file_dir / secrets_dir
        self.secrets_dir.mkdir(exist_ok=True)

        self.server_seed = server_seed if server_seed else self._read_or_create_tc2_seed(is_server=True)
        self.client_seed = client_seed if client_seed else self._read_or_create_tc2_seed(is_server=False)

        template_dir = self.file_dir / "templates"
        self.server_template = (template_dir / "server.template").read_text()
        self.client_template = (template_dir / "client.template").read_text()

    def _read_or_create_tc2_seed(self, is_server: bool = True) -> str:
        seed_file = self.secrets_dir / "tc2-seed.txt"
        if seed_file.exists() and is_server:
            return seed_file.read_text().strip()
        # Generate and save a strong seed
        seed = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
        seed_file.write_text(seed)
        seed_file.chmod(0o600)
        if is_server:
            print(f"Generated new tls-crypt-v2 server seed (saved to {seed_file})")
        return seed

    def derive_key(self, seed: str, is_server: bool = False) -> bytes:
        """
        Derive a key from seed data using PBKDF2.

        Args:
            seed: Seed data
            is_server: obvious, right? ;)
        Returns:
            Derived key bytes
        """
        # Create a deterministic salt based on key type
        salt = hashlib.sha256(f"openvpn-tls-crypt-v2".encode()).digest()

        # Use PBKDF2 to derive key from seed
        key = PBKDF2(
            password=seed,
            salt=salt,
            dkLen=self.SERVER_KEY_SIZE if is_server else self.CLIENT_KEY_SIZE,
            hmac_hash_module=SHA256
        )

        return key

    def wrap_client_key(self, server_key: bytes, client_key: bytes) -> bytes:
        """
        Create the wrapped client key (WKc) using the server key.

        This implements the OpenVPN TLS-crypt-v2 client key wrapping:
        WKc = T || AES-256-CTR(Ke, IV, Kc || metadata) || len

        Where:
        - T = HMAC-SHA256(Ka, len || Kc || metadata)
        - IV = first 128 bits of T
        - Ke = encryption key from server key
        - Ka = authentication key from server key

        Args:
            server_key: 128-byte server key
            client_key: 256-byte client key

        Returns:
            Wrapped client key bytes
        """
        # Extract Ke and Ka from server key
        # First 256 bits (32 bytes) of first 512-bit key for encryption
        ke = server_key[0:32]
        # First 256 bits (32 bytes) of second 512-bit key for authentication
        ka = server_key[64:96]

        # Generate metadata if not provided
        if self.metadata is None:
            # For deterministic generation, derive timestamp from seeds
            # This ensures same seeds always produce same metadata
            combined_seed = self.server_seed + self.client_seed
            timestamp_bytes = hashlib.sha256(combined_seed.encode() + b"timestamp").digest()[:8]
            timestamp = int.from_bytes(timestamp_bytes, 'big') % (2 ** 32)  # Keep it reasonable
            metadata = struct.pack('!BQ', self.METADATA_TYPE_TIMESTAMP, timestamp)
        else:
            metadata = self.metadata

        # Calculate wrapped key length
        # Tag (32) + encrypted data (256 + len(metadata)) + length field (2)
        wkc_len = self.TAG_SIZE + len(client_key) + len(metadata) + 2

        # Create length field (16-bit network byte order)
        len_bytes = struct.pack('!H', wkc_len)

        # Compute HMAC-SHA256 tag: T = HMAC-SHA256(Ka, len || Kc || metadata)
        h = hmac.new(ka, digestmod=hashlib.sha256)
        h.update(len_bytes)
        h.update(client_key)
        h.update(metadata)
        tag = h.digest()

        # Extract IV from tag (first 128 bits / 16 bytes)
        iv = tag[:16]

        # Convert IV to integer for CTR mode
        iv_int = int.from_bytes(iv, 'big')

        # Create AES-256-CTR cipher
        ctr = Counter.new(128, initial_value=iv_int)
        cipher = AES.new(ke, AES.MODE_CTR, counter=ctr)

        # Encrypt client key + metadata
        plaintext = client_key + metadata
        ciphertext = cipher.encrypt(plaintext)

        # Construct WKc: Tag || Ciphertext || Length
        wkc = tag + ciphertext + len_bytes

        return wkc

    # === CA ===
    @staticmethod
    def _load_ca(key_path: Path, crt_path: Path) -> CertPairDto:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
        return CertPairDto(key=key, cert=cert)

    def _create_ca(self, cn: str, valid_days: int = 3650):
        key_path = self.secrets_dir / "ca.key"
        cert_path = self.secrets_dir / "ca.crt"
        if key_path.exists() and cert_path.exists():
            return self._load_ca(key_path, cert_path)
        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True), True)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return CertPairDto(key=key, cert=cert)

    # === DH ===
    def _load_or_create_dh(self, key_size: int = 2048) -> DHParameters:
        dh_path = self.secrets_dir / "dh.pem"
        if dh_path.exists():
            return serialization.load_pem_parameters(dh_path.read_bytes())
        dh_params = dh.generate_parameters(generator=2, key_size=key_size)
        dh_path.write_bytes(dh_params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))
        return dh_params

    # === Certs ===
    @staticmethod
    def _gen_private_key():
        return rsa.generate_private_key(65537, 2048)

    def _create_cert(self, subject_name: str, is_server: bool, ca: CertPairDto, domain: str | None = None,
                     valid_days: int = 3650):
        pkey = self._gen_private_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
        builder = (
            x509.CertificateBuilder()
            .issuer_name(ca.cert.subject)
            .subject_name(subject)
            .public_key(pkey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=is_server,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(x509.ExtendedKeyUsage(
                [x509.ExtendedKeyUsageOID.SERVER_AUTH if is_server else x509.ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        )
        if domain and is_server:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), False)
        cert = builder.sign(ca.key, hashes.SHA256())
        return CertPairDto(key=pkey, cert=cert)

    @staticmethod
    def _pem(cert_pair: CertPairDto) -> tuple[str, str]:
        cert_pem = cert_pair.cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = cert_pair.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
        return cert_pem, key_pem

    @staticmethod
    def _dh_pem(dh_params) -> str:
        return dh_params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3).decode()

    @staticmethod
    def _tc2_to_pem(tc2: bytes, is_server: bool = False) -> str:
        b64_encoded = base64.b64encode(tc2).decode("utf-8")

        # Format into a PEM structure
        pem_output = f"-----BEGIN OpenVPN tls-crypt-v2 {'server' if is_server else 'client'} key-----\n"
        # Add line breaks for readability (optional but standard for PEM)
        pem_output += "\n".join([b64_encoded[i:i + 64] for i in range(0, len(b64_encoded), 64)])
        pem_output += f"\n-----END OpenVPN tls-crypt-v2 {'server' if is_server else 'client'} key-----\n"

        return pem_output

    # === Generation ===
    def generate_server(self, domain: str, port: int, proto: str):
        print("Generating server config...")
        ca = self._create_ca(domain)
        dh_params = self._load_or_create_dh()
        server_tc2 = self.derive_key(self.server_seed, True)

        server_pair = self._create_cert("server", True, ca, domain=domain)
        server_cert, server_key = self._pem(server_pair)
        ca_cert, _ = self._pem(ca)

        # Save server tls-crypt-v2 key to file (OpenVPN requires this)
        tc2_key_path = self.secrets_dir / "tls-crypt-v2-server.key"
        tc2_key_path.write_bytes(server_tc2)

        server_conf = self.server_template.format(
            port=port,
            proto=proto,
            ca_pem=ca_cert,
            cert_pem=server_cert,
            key_pem=server_key,
            dh_pem=self._dh_pem(dh_params),
            tls_crypt_pem=self._tc2_to_pem(server_tc2, is_server=True),
            # Note: server uses file path, not inline
        )
        configs_dir = self.file_dir / "configs"
        configs_dir.mkdir(exist_ok=True)
        (configs_dir / "server.conf").write_text(server_conf)
        print(f"Server config saved. tls-crypt-v2 key: {tc2_key_path}")

    def generate_clients(self, count: int, domain: str, port: int, proto: str):
        print(f"Generating {count} client configs...")
        # todo change to _load_ca on level of __init__ check if loaded here
        ca = self._create_ca("")
        ca_cert, _ = self._pem(ca)

        configs_dir = self.file_dir / "configs"
        configs_dir.mkdir(exist_ok=True)
        client_tc2 = self.derive_key(self.client_seed)
        server_tc2 = self.derive_key(self.server_seed, True)

        wkc = self.wrap_client_key(server_tc2, client_tc2)
        # Combine client key with wrapped key
        client_key_complete = client_tc2 + wkc
        for i in range(count):
            client_name = f"client_{i}"
            client_pair = self._create_cert(client_name, False, ca)
            client_cert, client_key = self._pem(client_pair)

            client_conf = self.client_template.format(
                proto=proto,
                server=domain,
                port=port,
                ca_pem=ca_cert,
                cert_pem=client_cert,
                key_pem=client_key,
                tls_crypt_pem=self._tc2_to_pem(client_key_complete),
            )
            (configs_dir / client_name).write_text(client_conf)
        print(f"Client configs saved to {configs_dir}")

    def generate_full(self, count: int, domain: str, port: int, proto: str):
        self.generate_server(domain, port, proto)
        self.generate_clients(count, domain, port, proto)


def main():
    parser = argparse.ArgumentParser(description="OpenVPN config generator with tls-crypt-v2")
    parser.add_argument(
        "--mode", choices=["full", "server", "clients"], default="full",
        help="Generation mode"
    )
    parser.add_argument(
        "--clients", type=int, default=1,
        help="Number of client configs to generate"
    )
    parser.add_argument(
        "--domain", default="gamerex.org",
        help="Server domain"
    )
    parser.add_argument(
        "--port", type=int, default=443,
        help="Server port"
    )
    parser.add_argument(
        "--proto", choices=["tcp", "udp"], default="tcp",
        help="Protocol"
    )

    args = parser.parse_args()
    if args.mode in ("clients", "full") and args.clients < 1:
        parser.error("--clients must be >= 1")

    gen = VpnConfigGenerator()
    if args.mode == "server":
        gen.generate_server(args.domain, args.port, args.proto)
    elif args.mode == "clients":
        gen.generate_clients(args.clients, args.domain, args.port, args.proto)
    else:
        gen.generate_full(args.clients, args.domain, args.port, args.proto)


if __name__ == "__main__":
    main()
