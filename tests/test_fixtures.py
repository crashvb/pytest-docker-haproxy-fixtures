#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""pytest fixture tests."""

import logging

from base64 import b64decode
from pathlib import Path
from ssl import SSLContext
from typing import Dict, List
from urllib import request as urllibrequest
from urllib3 import ProxyManager, Retry
from urllib3.exceptions import MaxRetryError

import pytest

from pytest_docker_haproxy_fixtures import (
    __version__,
    HAProxyCerts,
    HAProxyInsecure,
    HAProxySecure,
    HAPROXY_SERVICE_PATTERN,
)

LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def get_headers() -> Dict[str, str]:
    """Provides HTTP headers to be used when testing."""
    return {"User-Agent": f"pytest-docker-haproxy-fixtures/{__version__}"}


@pytest.fixture()
def known_good_endpoint() -> str:
    """Provides a known good endpoint for testing HTTP and HTTPS."""
    return "www.google.com"


# Override fixture for testing
@pytest.fixture(scope="session")
def pdhf_scale_factor() -> int:
    """Provides the number enumerated instances to be instantiated."""
    return 4


def no_duplicates(lst: List) -> bool:
    """Tests if a list contains duplicate values."""
    return len(lst) == len(set(lst))


def test_haproxy_auth_header(
    haproxy_auth_header,
    haproxy_password: str,
    haproxy_username: str,
):
    """Test that an HTTP basic authentication header can be provided."""
    assert "Proxy-Authorization" in haproxy_auth_header
    string = b64decode(
        haproxy_auth_header["Proxy-Authorization"].split()[1].encode("utf-8")
    ).decode("utf-8")
    assert haproxy_password in string
    assert haproxy_username in string


def test_haproxy_auth_header_list(
    haproxy_auth_header_list,
    haproxy_password_list: List[str],
    haproxy_username_list: List[str],
    pdhf_scale_factor: int,
):
    """Test that an HTTP basic authentication header can be provided."""
    for i in range(pdhf_scale_factor):
        assert "Proxy-Authorization" in haproxy_auth_header_list[i]
        string = b64decode(
            haproxy_auth_header_list[i]["Proxy-Authorization"]
            .split()[1]
            .encode("utf-8")
        ).decode("utf-8")
        assert haproxy_password_list[i] in string
        assert haproxy_username_list[i] in string
    assert no_duplicates([str(i) for i in haproxy_auth_header_list])
    assert no_duplicates(haproxy_password_list)
    assert no_duplicates(haproxy_username_list)


def test_haproxy_cacerts(haproxy_cacerts: Path, haproxy_certs: HAProxyCerts):
    """Test that a temporary CA certificate trust store can be provided."""
    assert haproxy_cacerts.exists()
    cacerts = haproxy_cacerts.read_text("utf-8")

    ca_cert = haproxy_certs.ca_certificate.read_text("utf-8")
    assert ca_cert in cacerts

    ca_key = haproxy_certs.ca_private_key.read_text("utf-8")
    assert ca_key not in cacerts

    cert = haproxy_certs.certificate.read_text("utf-8")
    assert cert not in cacerts

    key = haproxy_certs.private_key.read_text("utf-8")
    assert key not in cacerts


def test_haproxy_cacerts_list(
    haproxy_cacerts_list: List[Path],
    haproxy_certs_list: List[HAProxyCerts],
    pdhf_scale_factor: int,
):
    """Test that a temporary CA certificate trust store can be provided."""
    for i in range(pdhf_scale_factor):
        assert haproxy_cacerts_list[i].exists()
        cacerts = haproxy_cacerts_list[i].read_text("utf-8")

        ca_cert = haproxy_certs_list[i].ca_certificate.read_text("utf-8")
        assert ca_cert in cacerts

        ca_key = haproxy_certs_list[i].ca_private_key.read_text("utf-8")
        assert ca_key not in cacerts

        cert = haproxy_certs_list[i].certificate.read_text("utf-8")
        assert cert not in cacerts

        key = haproxy_certs_list[i].private_key.read_text("utf-8")
        assert key not in cacerts
    assert no_duplicates(haproxy_cacerts_list)
    assert no_duplicates(haproxy_certs_list)


def test_haproxy_certs(haproxy_certs: HAProxyCerts):
    """Test that a certificate and private key can be provided."""
    assert haproxy_certs.ca_certificate.exists()
    assert "BEGIN CERTIFICATE" in haproxy_certs.ca_certificate.read_text("utf-8")
    assert haproxy_certs.ca_private_key.exists()
    assert "BEGIN PRIVATE KEY" in haproxy_certs.ca_private_key.read_text("utf-8")
    assert haproxy_certs.certificate.exists()
    assert "BEGIN CERTIFICATE" in haproxy_certs.certificate.read_text("utf-8")
    assert haproxy_certs.private_key.exists()
    assert "BEGIN PRIVATE KEY" in haproxy_certs.private_key.read_text("utf-8")


def test_haproxy_certs_list(
    haproxy_certs_list: List[HAProxyCerts], pdhf_scale_factor: int
):
    """Test that a certificate and private key can be provided."""
    for i in range(pdhf_scale_factor):
        assert haproxy_certs_list[i].ca_certificate.exists()
        assert "BEGIN CERTIFICATE" in haproxy_certs_list[i].ca_certificate.read_text(
            "utf-8"
        )
        assert haproxy_certs_list[i].ca_private_key.exists()
        assert "BEGIN PRIVATE KEY" in haproxy_certs_list[i].ca_private_key.read_text(
            "utf-8"
        )
        assert haproxy_certs_list[i].certificate.exists()
        assert "BEGIN CERTIFICATE" in haproxy_certs_list[i].certificate.read_text(
            "utf-8"
        )
        assert haproxy_certs_list[i].private_key.exists()
        assert "BEGIN PRIVATE KEY" in haproxy_certs_list[i].private_key.read_text(
            "utf-8"
        )
    assert no_duplicates(haproxy_certs_list)


def test_haproxy_haproxycfg_insecure(
    haproxy_haproxycfg_insecure: Path,
):
    """Test that an insecure haproxy.cfg can be provided."""
    assert haproxy_haproxycfg_insecure.exists()
    content = haproxy_haproxycfg_insecure.read_text("utf-8")
    assert len(content) > 0


def test_haproxy_haproxycfg_insecure_list(
    haproxy_haproxycfg_insecure_list: List[Path],
    pdhf_scale_factor: int,
):
    """Test that an insecure haproxy.cfg can be provided."""
    for i in range(pdhf_scale_factor):
        assert haproxy_haproxycfg_insecure_list[i].exists()
        content = haproxy_haproxycfg_insecure_list[i].read_text("utf-8")
        assert len(content) > 0
    assert no_duplicates(haproxy_haproxycfg_insecure_list)


def test_haproxy_haproxycfg_secure(
    haproxy_haproxycfg_secure: Path,
    haproxy_password: str,
    haproxy_username: str,
):
    """Test that a secure haproxy.cfg can be provided."""
    assert haproxy_haproxycfg_secure.exists()
    content = haproxy_haproxycfg_secure.read_text("utf-8")
    assert len(content)
    assert haproxy_password in content
    assert haproxy_username in content


def test_haproxy_haproxycfg_secure_list(
    haproxy_haproxycfg_secure_list: List[Path],
    pdhf_scale_factor: int,
):
    """Test that a secure haproxy.cfg can be provided."""
    for i in range(pdhf_scale_factor):
        assert haproxy_haproxycfg_secure_list[i].exists()
        content = haproxy_haproxycfg_secure_list[i].read_text("utf-8")
        assert len(content) > 0
    assert no_duplicates(haproxy_haproxycfg_secure_list)


@pytest.mark.online
def test_haproxy_insecure(
    get_headers: Dict[str, str],
    haproxy_insecure: HAProxyInsecure,
    known_good_endpoint: str,
):
    """Test that an insecure haproxy can be instantiated."""
    assert "127.0.0.1" in haproxy_insecure.endpoint

    request = urllibrequest.Request(
        headers=get_headers, method="HEAD", url=f"http://{known_good_endpoint}/"
    )
    request.set_proxy(host=haproxy_insecure.endpoint, type="http")
    with urllibrequest.urlopen(url=request) as response:
        assert response.code == 200


@pytest.mark.online
def test_haproxy_insecure_content(
    get_headers: Dict[str, str],
    haproxy_insecure: HAProxyInsecure,
    known_good_endpoint: str,
):
    """Test that an insecure haproxy can be instantiated."""
    assert "127.0.0.1" in haproxy_insecure.endpoint

    request = urllibrequest.Request(
        headers=get_headers, url=f"http://{known_good_endpoint}/"
    )
    request.set_proxy(host=haproxy_insecure.endpoint, type="http")
    with urllibrequest.urlopen(url=request) as response:
        assert response.code == 200
        # TODO: Why doesn't decoding to utf-8 work?
        assert "doctype" in str(response.read()).lower()


@pytest.mark.online
def test_haproxy_insecure_proxymanager(
    get_headers: Dict[str, str],
    haproxy_insecure: HAProxyInsecure,
    known_good_endpoint: str,
):
    """Test that an insecure haproxy can be instantiated."""
    assert "127.0.0.1" in haproxy_insecure.endpoint

    retry = Retry(total=0)

    proxy_manager = ProxyManager(
        headers=get_headers,
        proxy_headers=get_headers,
        proxy_url=f"http://{haproxy_insecure.endpoint}/",
    )
    response = proxy_manager.request(
        method="HEAD", retries=retry, url=f"http://{known_good_endpoint}/"
    )
    assert response.status == 200


@pytest.mark.online
def test_haproxy_insecure_list(
    get_headers: Dict[str, str],
    haproxy_insecure_list: List[HAProxyInsecure],
    known_good_endpoint: str,
    pdhf_scale_factor: int,
):
    """Test that an insecure haproxy can be instantiated."""
    for i in range(pdhf_scale_factor):
        assert "127.0.0.1" in haproxy_insecure_list[i].endpoint

        request = urllibrequest.Request(
            headers=get_headers, method="HEAD", url=f"http://{known_good_endpoint}/"
        )
        request.set_proxy(host=haproxy_insecure_list[i].endpoint, type="http")
        with urllibrequest.urlopen(url=request) as response:
            assert response.code == 200

    assert no_duplicates([str(i) for i in haproxy_insecure_list])


def test_haproxy_password(haproxy_password: str):
    """Test that a password can be provided."""
    assert haproxy_password


def test_haproxy_password_list(
    haproxy_password_list: List[str], pdhf_scale_factor: int
):
    """Test that a password can be provided."""
    for i in range(pdhf_scale_factor):
        assert haproxy_password_list[i]
    assert no_duplicates(haproxy_password_list)


@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
@pytest.mark.online
def test_haproxy_secure(
    get_headers: Dict[str, str],
    haproxy_secure: HAProxySecure,
    known_good_endpoint: str,
):
    """Test that an secure haproxy can be instantiated."""
    assert "127.0.0.1" in haproxy_secure.endpoint

    haproxy_secure.ssl_context.check_hostname = False
    retry = Retry(total=0)

    proxy_manager = ProxyManager(
        headers=get_headers,
        proxy_headers={**get_headers, **haproxy_secure.auth_header},
        # proxy_ssl_context=haproxy_secure.ssl_context,
        proxy_url=f"https://{haproxy_secure.endpoint}/",
        ssl_context=haproxy_secure.ssl_context,
        use_forwarding_for_https=True,
    )
    response = proxy_manager.request(
        method="HEAD", retries=retry, url=f"https://{known_good_endpoint}/"
    )
    assert response.status == 200

    # Error: Unauthenticated
    with pytest.raises(MaxRetryError) as exception_info:
        proxy_manager = ProxyManager(
            headers=get_headers,
            proxy_headers=get_headers,
            proxy_ssl_context=haproxy_secure.ssl_context,
            proxy_url=f"https://{haproxy_secure.endpoint}/",
        )
        proxy_manager.request(
            method="HEAD", retries=retry, url=f"https://{known_good_endpoint}/"
        )
    assert "401" in str(exception_info.value)

    # Error: CA not trusted
    with pytest.raises(MaxRetryError) as exception_info:
        proxy_manager = ProxyManager(
            headers=get_headers,
            proxy_headers={**get_headers, **haproxy_secure.auth_header},
            proxy_url=f"https://{haproxy_secure.endpoint}/",
        )
        proxy_manager.request(
            method="HEAD", retries=retry, url=f"https://{known_good_endpoint}/"
        )
    assert "CERTIFICATE_VERIFY_FAILED" in str(exception_info.value)


@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
@pytest.mark.online
def test_haproxy_secure_content(
    get_headers: Dict[str, str],
    haproxy_secure: HAProxySecure,
    known_good_endpoint: str,
):
    """Test that an secure haproxy can be instantiated."""
    assert "127.0.0.1" in haproxy_secure.endpoint

    haproxy_secure.ssl_context.check_hostname = False
    retry = Retry(total=0)

    proxy_manager = ProxyManager(
        headers=get_headers,
        proxy_headers={**get_headers, **haproxy_secure.auth_header},
        # proxy_ssl_context=haproxy_secure.ssl_context,
        proxy_url=f"https://{haproxy_secure.endpoint}/",
        ssl_context=haproxy_secure.ssl_context,
        use_forwarding_for_https=True,
    )
    response = proxy_manager.request(
        method="GET", retries=retry, url=f"https://{known_good_endpoint}/"
    )
    assert response.status == 200
    # TODO: Why doesn't decoding to utf-8 work?
    assert "doctype" in str(response.data).lower()


@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
@pytest.mark.online
def test_haproxy_secure_list(
    get_headers: Dict[str, str],
    haproxy_secure_list: List[HAProxySecure],
    known_good_endpoint: str,
    pdhf_scale_factor: int,
):
    """Test that an secure haproxy can be instantiated."""
    for i in range(pdhf_scale_factor):
        assert "127.0.0.1" in haproxy_secure_list[i].endpoint

        haproxy_secure_list[i].ssl_context.check_hostname = False
        retry = Retry(total=0)

        proxy_manager = ProxyManager(
            headers=get_headers,
            proxy_headers={**get_headers, **haproxy_secure_list[i].auth_header},
            # proxy_ssl_context=haproxy_secure_list[i].ssl_context,
            proxy_url=f"https://{haproxy_secure_list[i].endpoint}/",
            ssl_context=haproxy_secure_list[i].ssl_context,
            use_forwarding_for_https=True,
        )
        response = proxy_manager.request(
            method="HEAD", retries=retry, url=f"https://{known_good_endpoint}/"
        )
        assert response.status == 200

        # Error: Unauthenticated
        with pytest.raises(MaxRetryError) as exception_info:
            proxy_manager = ProxyManager(
                headers=get_headers,
                proxy_headers=get_headers,
                # proxy_ssl_context=haproxy_secure_list[i].ssl_context,
                proxy_url=f"https://{haproxy_secure_list[i].endpoint}/",
                ssl_context=haproxy_secure_list[i].ssl_context,
            )
            proxy_manager.request(
                method="HEAD", retries=retry, url=f"https://{known_good_endpoint}/"
            )
        assert "401" in str(exception_info.value)

        # Error: CA not trusted
        with pytest.raises(MaxRetryError) as exception_info:
            proxy_manager = ProxyManager(
                headers=get_headers,
                proxy_headers={**get_headers, **haproxy_secure_list[i].auth_header},
                proxy_url=f"https://{haproxy_secure_list[i].endpoint}/",
            )
            proxy_manager.request(
                method="HEAD", retries=retry, url=f"https://{known_good_endpoint}/"
            )
        assert "CERTIFICATE_VERIFY_FAILED" in str(exception_info.value)
    assert no_duplicates([str(i) for i in haproxy_secure_list])


def test_haproxy_ssl_context(haproxy_ssl_context: SSLContext):
    """Test that an ssl context can be provided."""
    assert isinstance(haproxy_ssl_context, SSLContext)


def test_haproxy_ssl_context_list(
    haproxy_ssl_context_list: List[SSLContext], pdhf_scale_factor: int
):
    """Test that an ssl context can be provided."""
    for i in range(pdhf_scale_factor):
        assert isinstance(haproxy_ssl_context_list[i], SSLContext)
    assert no_duplicates(haproxy_ssl_context_list)


def test_haproxy_username(haproxy_username: str):
    """Test that a username can be provided."""
    assert haproxy_username


def test_haproxy_username_list(
    haproxy_username_list: List[str], pdhf_scale_factor: int
):
    """Test that a username can be provided."""
    for i in range(pdhf_scale_factor):
        assert haproxy_username_list[i]
    assert no_duplicates(haproxy_username_list)


def test_pdhf_docker_compose_insecure(pdhf_docker_compose_insecure: Path):
    """Test that the embedded docker-compose for insecure haproxy can be copied to a temporary file."""
    service_name = HAPROXY_SERVICE_PATTERN.format("insecure", 0)
    assert service_name in pdhf_docker_compose_insecure.read_text()


def test_pdhf_docker_compose_insecure_list(
    pdhf_docker_compose_insecure_list: List[Path], pdhf_scale_factor: int
):
    """Test that the embedded docker-compose for insecure haproxy can be copied to a temporary file."""
    for i in range(pdhf_scale_factor):
        service_name = HAPROXY_SERVICE_PATTERN.format("insecure", i)
        assert service_name in pdhf_docker_compose_insecure_list[i].read_text()
    assert no_duplicates(pdhf_docker_compose_insecure_list)


def test_pdhf_docker_compose_secure(pdhf_docker_compose_secure: Path):
    """Test that the embedded docker-compose for secure haproxy can be copied to a temporary file."""
    service_name = HAPROXY_SERVICE_PATTERN.format("secure", 0)
    assert service_name in pdhf_docker_compose_secure.read_text()


def test_pdhf_docker_compose_secure_list(
    pdhf_docker_compose_secure_list: List[Path], pdhf_scale_factor: int
):
    """Test that the embedded docker-compose for secure haproxy can be copied to a temporary file."""
    for i in range(pdhf_scale_factor):
        service_name = HAPROXY_SERVICE_PATTERN.format("secure", i)
        assert service_name in pdhf_docker_compose_secure_list[i].read_text()
    assert no_duplicates(pdhf_docker_compose_secure_list)
