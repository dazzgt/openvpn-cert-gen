import os
import base64
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.x509.oid import NameOID


@dataclass
class CertPairDto:
    key: rsa.RSAPrivateKey
    cert: x509.Certificate


class VpnConfigGenerator:
    def __init__(self, secrets_dir: str = "secrets"):
        self.file_dir = Path(__file__).parent
        self.secrets_dir = self.file_dir / secrets_dir
        self.secrets_dir.mkdir(exist_ok=True)

        template_dir = self.file_dir / "templates"
        self.server_template = (template_dir / "server.template").read_text()
        self.client_template = (template_dir / "client.template").read_text()

    # === CA ===
    def _load_or_create_ca(self, valid_days: int = 3650):
        key_path = self.secrets_dir / "ca.key"
        cert_path = self.secrets_dir / "ca.crt"

        if key_path.exists() and cert_path.exists():
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            return CertPairDto(key=key, cert=cert)

        # Generate new CA
        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gamerex.org")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return CertPairDto(key=key, cert=cert)

    # === DH ===
    def _load_or_create_dh(self, key_size: int = 2048):
        dh_path = self.secrets_dir / "dh.pem"
        if dh_path.exists():
            return serialization.load_pem_parameters(dh_path.read_bytes())
        dh_params = dh.generate_parameters(generator=2, key_size=key_size)
        dh_path.write_bytes(
            dh_params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
        )
        return dh_params

    # === TLS-CRYPT ===
    def _load_or_create_tls_crypt(self):
        key_path = self.secrets_dir / "tls-crypt.key"
        if key_path.exists():
            return key_path.read_text()
        raw = os.urandom(512)
        b64_lines = [base64.b64encode(raw[i:i+64]).decode() for i in range(0, 512, 64)]
        pem = (
            "-----BEGIN OpenVPN Static key V1-----\n"
            + "\n".join(b64_lines)
            + "\n-----END OpenVPN Static key V1-----\n"
        )
        key_path.write_text(pem)
        return pem

    # === Certs ===
    def _gen_private_key(self):
        return rsa.generate_private_key(65537, 2048)

    def _create_cert(self, subject_name: str, is_server: bool, ca: CertPairDto, domain: str | None = None, valid_days: int = 3650):
        pkey = self._gen_private_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
        builder = x509.CertificateBuilder()
        builder = (
            builder
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
            .add_extension(
                x509.ExtendedKeyUsage(
                    [x509.ExtendedKeyUsageOID.SERVER_AUTH if is_server else x509.ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                False,
            )
        )
        if domain and is_server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]), False
            )
        cert = builder.sign(ca.key, hashes.SHA256())
        return CertPairDto(key=pkey, cert=cert)

    # === PEM helpers ===
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
        return dh_params.parameter_bytes(
            serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3
        ).decode()

    # === Main ===
    def generate_config(self, count: int, domain: str, port: int, proto: str = "tcp"):
        print("Loading or creating secrets...")
        ca = self._load_or_create_ca()
        dh_params = self._load_or_create_dh()
        tls_crypt = self._load_or_create_tls_crypt()

        configs_dir = self.file_dir / "configs"
        configs_dir.mkdir(exist_ok=True)

        # Server cert
        server_pair = self._create_cert("server", True, ca, domain=domain)
        server_cert, server_key = self._pem(server_pair)
        ca_cert, _ = self._pem(ca)

        # Write server config
        server_conf = self.server_template.format(
            port=port,
            proto=proto,
            ca_pem=ca_cert,
            cert_pem=server_cert,
            key_pem=server_key,
            dh_pem=self._dh_pem(dh_params),
            tls_crypt_pem=tls_crypt,
        )
        (configs_dir / "server.conf").write_text(server_conf)

        # Client configs
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
                tls_crypt_pem=tls_crypt,
            )
            (configs_dir / client_name).write_text(client_conf)

        print(f"Done. Configs in {configs_dir}, secrets in {self.secrets_dir}")


if __name__ == "__main__":
    VpnConfigGenerator().generate_config(
        count=10,
        domain="gamerex.org",
        port=443,
        proto="tcp"
    )