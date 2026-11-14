from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
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
        use_system_trust_store=False,
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


def test_get_system_trust_store_certificates():
    certs = tls.get_system_trust_store_certificates()
    # Any real system has at least one root CA in its trust store.
    assert certs
    assert all(isinstance(c, x509.Certificate) for c in certs)
    # Results are cached to avoid repeated store enumeration.
    assert tls.get_system_trust_store_certificates() is certs


def _do_handshake(client: SSL.Connection, server: SSL.Connection) -> None:
    read, write = client, server
    while True:
        try:
            read.do_handshake()
        except SSL.WantReadError:
            write.bio_write(read.bio_read(2**16))
        else:
            break
        read, write = write, read


@pytest.mark.parametrize("use_system_trust_store", [True, False])
def test_create_proxy_server_context_system_trust_store(
    tdata, monkeypatch, use_system_trust_store
):
    """
    A CA that is only present in the OS trust store must be accepted if and only if
    use_system_trust_store is enabled.
    """
    root = x509.load_pem_x509_certificate(
        Path(
            tdata.path("mitmproxy/net/data/verificationcerts/trusted-root.crt")
        ).read_bytes()
    )
    monkeypatch.setattr(tls, "get_system_trust_store_certificates", lambda: (root,))
    tls.create_proxy_server_context.cache_clear()
    tls.create_client_proxy_context.cache_clear()
    try:
        cctx = tls.create_proxy_server_context(
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
            use_system_trust_store=use_system_trust_store,
        )
    finally:
        tls.create_proxy_server_context.cache_clear()

    sctx = tls.create_client_proxy_context(
        method=tls.Method.TLS_SERVER_METHOD,
        min_version=tls.DEFAULT_MIN_VERSION,
        max_version=tls.DEFAULT_MAX_VERSION,
        cipher_list=None,
        ecdh_curve=None,
        chain_file=None,
        alpn_select_callback=None,
        request_client_cert=False,
        extra_chain_certs=(),
        dhparams=None,
    )
    sctx.use_certificate_chain_file(
        tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.crt")
    )
    sctx.use_privatekey_file(
        tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.key")
    )

    server = SSL.Connection(sctx)
    server.set_accept_state()
    client = SSL.Connection(cctx)
    client.set_connect_state()

    if use_system_trust_store:
        _do_handshake(client, server)
    else:
        with pytest.raises(SSL.Error, match="certificate verify failed"):
            _do_handshake(client, server)
