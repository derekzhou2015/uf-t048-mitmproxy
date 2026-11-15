from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import crypto
from OpenSSL import SSL

from mitmproxy import certs
from mitmproxy.net import tls


@pytest.mark.parametrize("version", [tls.Version.UNBOUNDED, tls.Version.SSL3])
def test_supported(version):
    # wild assumption: test environments should not do SSLv3 by default.
    expected_support = version is tls.Version.UNBOUNDED
    assert tls.is_supported_version(version) == expected_support


def test_make_master_secret_logger():
    assert tls.make_master_secret_logger(None) is None
    assert isinstance(tls.make_master_secret_logger("filepath"), tls.MasterSecretLogger)


def test_sslkeylogfile(tdata, monkeypatch):
    keylog = []
    monkeypatch.setattr(
        tls, "log_master_secret", lambda conn, secrets: keylog.append(secrets)
    )

    store = certs.CertStore.from_files(
        Path(tdata.path("mitmproxy/net/data/verificationcerts/trusted-root.pem")),
        Path(tdata.path("mitmproxy/net/data/dhparam.pem")),
    )
    entry = store.get_cert("example.com", [], None)

    cctx = tls.create_proxy_server_context(
        method=tls.Method.TLS_CLIENT_METHOD,
        min_version=tls.DEFAULT_MIN_VERSION,
        max_version=tls.DEFAULT_MAX_VERSION,
        cipher_list=None,
        ecdh_curve=None,
        verify=tls.Verify.VERIFY_NONE,
        ca_path=None,
        ca_pemfile=None,
        client_cert=None,
        legacy_server_connect=False,
        use_system_store=False,
    )
    sctx = tls.create_client_proxy_context(
        method=tls.Method.TLS_SERVER_METHOD,
        min_version=tls.DEFAULT_MIN_VERSION,
        max_version=tls.DEFAULT_MAX_VERSION,
        cipher_list=None,
        ecdh_curve=None,
        chain_file=entry.chain_file,
        alpn_select_callback=None,
        request_client_cert=False,
        extra_chain_certs=(),
        dhparams=store.dhparams,
    )

    server = SSL.Connection(sctx)
    server.set_accept_state()

    server.use_certificate(entry.cert.to_cryptography())
    server.use_privatekey(entry.privatekey)

    client = SSL.Connection(cctx)
    client.set_connect_state()

    read, write = client, server
    while True:
        try:
            read.do_handshake()
        except SSL.WantReadError:
            write.bio_write(read.bio_read(2**16))
        else:
            break
        read, write = write, read

    assert keylog
    assert keylog[0].startswith(b"SERVER_HANDSHAKE_TRAFFIC_SECRET")


def test_is_record_magic():
    assert not tls.starts_like_tls_record(b"POST /")
    assert not tls.starts_like_tls_record(b"\x16\x03\x04")
    assert not tls.starts_like_tls_record(b"")
    assert not tls.starts_like_tls_record(b"\x16")
    assert not tls.starts_like_tls_record(b"\x16\x03")
    assert tls.starts_like_tls_record(b"\x16\x03\x00")
    assert tls.starts_like_tls_record(b"\x16\x03\x01")
    assert tls.starts_like_tls_record(b"\x16\x03\x02")
    assert tls.starts_like_tls_record(b"\x16\x03\x03")
    assert not tls.starts_like_tls_record(bytes.fromhex("16fefe"))


def test_is_dtls_record_magic():
    assert not tls.starts_like_dtls_record(bytes.fromhex(""))
    assert not tls.starts_like_dtls_record(bytes.fromhex("16"))
    assert not tls.starts_like_dtls_record(bytes.fromhex("16fe"))
    assert tls.starts_like_dtls_record(bytes.fromhex("16fefd"))
    assert tls.starts_like_dtls_record(bytes.fromhex("16fefe"))
    assert not tls.starts_like_dtls_record(bytes.fromhex("160300"))
    assert not tls.starts_like_dtls_record(bytes.fromhex("160304"))
    assert not tls.starts_like_dtls_record(bytes.fromhex("150301"))


def test_get_curve():
    assert isinstance(tls.get_curve("secp256r1"), ec.SECP256R1)


def test_system_trusted_ca_pem():
    pem = tls.system_trusted_ca_pem()
    system_certs = x509.load_pem_x509_certificates(pem)
    assert system_certs
    # certificates must be deduplicated: some platforms list the same CA
    # in multiple system stores, and OpenSSL must not choke on duplicates.
    ders = [c.public_bytes(Encoding.DER) for c in system_certs]
    assert len(ders) == len(set(ders))


def test_create_proxy_server_context_system_store(tdata, monkeypatch):
    root_pem = Path(
        tdata.path("mitmproxy/net/data/verificationcerts/trusted-root.crt")
    ).read_bytes()
    root_der = x509.load_pem_x509_certificate(root_pem).public_bytes(Encoding.DER)
    monkeypatch.setattr(tls, "_system_trusted_ca_certs_der", lambda: (root_der,))

    leaf = crypto.load_certificate(
        crypto.FILETYPE_PEM,
        Path(
            tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.crt")
        ).read_bytes(),
    )

    def make_ctx(use_system_store: bool) -> SSL.Context:
        return tls.create_proxy_server_context(
            method=tls.Method.TLS_CLIENT_METHOD,
            min_version=tls.DEFAULT_MIN_VERSION,
            max_version=tls.DEFAULT_MAX_VERSION,
            cipher_list=None,
            ecdh_curve=None,
            verify=tls.Verify.VERIFY_PEER,
            ca_path=None,
            ca_pemfile=None,
            client_cert=None,
            legacy_server_connect=False,
            use_system_store=use_system_store,
        )

    # the test root CA is not part of the certifi bundle...
    with pytest.raises(crypto.X509StoreContextError):
        crypto.X509StoreContext(
            make_ctx(False).get_cert_store(), leaf
        ).verify_certificate()
    # ...but it is trusted once the (mocked) system store is hooked in.
    crypto.X509StoreContext(make_ctx(True).get_cert_store(), leaf).verify_certificate()
