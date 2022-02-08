#!/usr/bin/env python

# pylint: disable=redefined-outer-name,too-many-arguments,too-many-locals

"""The actual fixtures, you found them ;)."""

import logging
import itertools

from base64 import b64encode
from functools import partial
from pathlib import Path
from ssl import create_default_context, SSLContext
from string import Template
from time import sleep, time
from typing import Dict, Generator, List, NamedTuple

import pytest

from lovely.pytest.docker.compose import Services
from _pytest.tmpdir import TempPathFactory

from .utils import (
    check_proxy,
    generate_cacerts,
    generate_haproxycfg,
    generate_keypair,
    get_docker_compose_user_defined,
    get_embedded_file,
    get_user_defined_file,
    HAPROXY_PORT_INSECURE,
    HAPROXY_PORT_SECURE,
    HAPROXY_SERVICE,
    HAPROXY_SERVICE_PATTERN,
    start_service,
)

# Caching is needed, as singular-fixtures and list-fixtures will conflict at scale_factor=1
# This appears to only matter when attempting to start the docker secure haproxy service
# for the second time.
CACHE = {}

LOGGER = logging.getLogger(__name__)


class HAProxyCerts(NamedTuple):
    # pylint: disable=missing-class-docstring
    ca_certificate: Path
    ca_private_key: Path
    certificate: Path
    private_key: Path


class HAProxyInsecure(NamedTuple):
    # pylint: disable=missing-class-docstring
    docker_compose: Path
    endpoint: str
    endpoint_name: str
    service_name: str


# Note: NamedTuple does not support inheritance :(
class HAProxySecure(NamedTuple):
    # pylint: disable=missing-class-docstring
    auth_header: Dict[str, str]
    cacerts: Path
    certs: HAProxyCerts
    docker_compose: Path
    endpoint: str
    endpoint_name: str
    password: str
    service_name: str
    ssl_context: SSLContext
    username: str


def _haproxy_auth_header(
    *,
    haproxy_password_list: List[str],
    haproxy_username_list: List[str],
    scale_factor: int,
) -> List[Dict[str, str]]:
    """Provides an HTTP basic authentication header containing credentials for the secure haproxy service."""
    cache_key = _haproxy_auth_header.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        auth = b64encode(
            f"{haproxy_username_list[i]}:{haproxy_password_list[i]}".encode("utf-8")
        ).decode("utf-8")
        result.append({"Proxy-Authorization": f"Basic {auth}"})
    CACHE[cache_key] = result
    return result


@pytest.fixture(scope="session")
def haproxy_auth_header(haproxy_password: str, haproxy_username: str) -> Dict[str, str]:
    """Provides an HTTP basic authentication header containing credentials for the secure haproxy service."""
    return _haproxy_auth_header(
        haproxy_password_list=[haproxy_password],
        haproxy_username_list=[haproxy_username],
        scale_factor=1,
    )[0]


@pytest.fixture(scope="session")
def haproxy_auth_header_list(
    haproxy_password_list: List[str],
    haproxy_username_list: List[str],
    pdhf_scale_factor: int,
) -> List[Dict[str, str]]:
    """Provides an HTTP basic authentication header containing credentials for the secure haproxy service."""
    return _haproxy_auth_header(
        haproxy_password_list=haproxy_password_list,
        haproxy_username_list=haproxy_username_list,
        scale_factor=pdhf_scale_factor,
    )


def _haproxy_cacerts(
    *,
    haproxy_certs_list: List[HAProxyCerts],
    pytestconfig: "_pytest.config.Config",
    scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """
    Provides the location of a temporary CA certificate trust store that contains the certificate of the secure haproxy
    service.
    """
    cache_key = _haproxy_cacerts.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        chain = itertools.chain(
            get_user_defined_file(pytestconfig, "cacerts"),
            generate_cacerts(
                tmp_path_factory,
                certificate=haproxy_certs_list[i].ca_certificate,
            ),
        )
        for path in chain:
            result.append(path)
            break
        else:
            LOGGER.warning("Unable to find or generate cacerts!")
            result.append("-unknown-")
    CACHE[cache_key] = result
    yield result


@pytest.fixture(scope="session")
def haproxy_cacerts(
    haproxy_certs: HAProxyCerts,
    pytestconfig: "_pytest.config.Config",
    tmp_path_factory: TempPathFactory,
) -> Generator[Path, None, None]:
    """
    Provides the location of a temporary CA certificate trust store that contains the certificate of the secure haproxy
    service.
    """
    for lst in _haproxy_cacerts(
        haproxy_certs_list=[haproxy_certs],
        pytestconfig=pytestconfig,
        scale_factor=1,
        tmp_path_factory=tmp_path_factory,
    ):
        yield lst[0]


@pytest.fixture(scope="session")
def haproxy_cacerts_list(
    haproxy_certs_list: List[HAProxyCerts],
    pdhf_scale_factor: int,
    pytestconfig: "_pytest.config.Config",
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """
    Provides the location of a temporary CA certificate trust store that contains the certificate of the secure haproxy
    service.
    """
    yield from _haproxy_cacerts(
        haproxy_certs_list=haproxy_certs_list,
        pytestconfig=pytestconfig,
        scale_factor=pdhf_scale_factor,
        tmp_path_factory=tmp_path_factory,
    )


def _haproxy_certs(
    *, scale_factor: int, tmp_path_factory: TempPathFactory
) -> Generator[List[HAProxyCerts], None, None]:
    """Provides the location of temporary certificate and private key files for the secure haproxy service."""
    # TODO: Augment to allow for reading certificates from /test ...
    cache_key = _haproxy_certs.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        tmp_path = tmp_path_factory.mktemp(__name__)
        keypair = generate_keypair()
        haproxy_cert = HAProxyCerts(
            ca_certificate=tmp_path.joinpath(f"{HAPROXY_SERVICE}-ca-{i}.crt"),
            ca_private_key=tmp_path.joinpath(f"{HAPROXY_SERVICE}-ca-{i}.key"),
            certificate=tmp_path.joinpath(f"{HAPROXY_SERVICE}-{i}.crt"),
            private_key=tmp_path.joinpath(f"{HAPROXY_SERVICE}-{i}.key"),
        )
        haproxy_cert.ca_certificate.write_bytes(keypair.ca_certificate)
        haproxy_cert.ca_private_key.write_bytes(keypair.ca_private_key)
        haproxy_cert.certificate.write_bytes(keypair.certificate)
        haproxy_cert.private_key.write_bytes(keypair.private_key)
        result.append(haproxy_cert)
    CACHE[cache_key] = result
    yield result
    for haproxy_cert in result:
        haproxy_cert.ca_certificate.unlink(missing_ok=True)
        haproxy_cert.ca_private_key.unlink(missing_ok=True)
        haproxy_cert.certificate.unlink(missing_ok=True)
        haproxy_cert.private_key.unlink(missing_ok=True)


@pytest.fixture(scope="session")
def haproxy_certs(
    tmp_path_factory: TempPathFactory,
) -> Generator[HAProxyCerts, None, None]:
    """Provides the location of temporary certificate and private key files for the secure haproxy service."""
    for lst in _haproxy_certs(scale_factor=1, tmp_path_factory=tmp_path_factory):
        yield lst[0]


@pytest.fixture(scope="session")
def haproxy_certs_list(
    pdhf_scale_factor: int, tmp_path_factory: TempPathFactory
) -> Generator[List[HAProxyCerts], None, None]:
    """Provides the location of temporary certificate and private key files for the secure haproxy service."""
    yield from _haproxy_certs(
        scale_factor=pdhf_scale_factor, tmp_path_factory=tmp_path_factory
    )


def _haproxy_haproxycfg_insecure(
    *,
    pytestconfig: "_pytest.config.Config",
    scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """Provides the location of the haproxy configuration file for the insecure haproxy service."""
    cache_key = _haproxy_haproxycfg_insecure.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        chain = itertools.chain(
            get_user_defined_file(pytestconfig, "haproxy.insecure.cfg"),
            get_embedded_file(
                tmp_path_factory, delete_after=False, name="haproxy.insecure.cfg"
            ),
        )
        for path in chain:
            result.append(path)
            break
        else:
            LOGGER.warning("Unable to find insecure haproxy.cfg!")
            result.append("-unknown-")
    CACHE[cache_key] = result
    yield result


@pytest.fixture(scope="session")
def haproxy_haproxycfg_insecure(
    pytestconfig: "_pytest.config.Config",
    tmp_path_factory: TempPathFactory,
) -> Generator[Path, None, None]:
    """Provides the location of the haproxy configuration  file for the insecure haproxy service."""
    for lst in _haproxy_haproxycfg_insecure(
        pytestconfig=pytestconfig,
        scale_factor=1,
        tmp_path_factory=tmp_path_factory,
    ):
        yield lst[0]


@pytest.fixture(scope="session")
def haproxy_haproxycfg_insecure_list(
    pdhf_scale_factor: int,
    pytestconfig: "_pytest.config.Config",
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """Provides the location of the haproxy configuration file for the insecure haproxy service."""
    yield from _haproxy_haproxycfg_insecure(
        pytestconfig=pytestconfig,
        scale_factor=pdhf_scale_factor,
        tmp_path_factory=tmp_path_factory,
    )


def _haproxy_haproxycfg_secure(
    *,
    haproxy_password_list: List[str],
    haproxy_username_list: List[str],
    pytestconfig: "_pytest.config.Config",
    scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """Provides the location of the haproxy configuration file for the secure haproxy service."""
    cache_key = _haproxy_haproxycfg_secure.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        chain = itertools.chain(
            get_user_defined_file(pytestconfig, "haproxy.secure.cfg"),
            generate_haproxycfg(
                tmp_path_factory,
                username=haproxy_username_list[i],
                password=haproxy_password_list[i],
            ),
        )
        for path in chain:
            result.append(path)
            break
        else:
            LOGGER.warning("Unable to find secure haproxy.cfg!")
            result.append("-unknown-")
    CACHE[cache_key] = result
    yield result


@pytest.fixture(scope="session")
def haproxy_haproxycfg_secure(
    haproxy_password_list: List[str],
    haproxy_username_list: List[str],
    pytestconfig: "_pytest.config.Config",
    tmp_path_factory: TempPathFactory,
) -> Generator[Path, None, None]:
    """Provides the location of the haproxy configuration  file for the secure haproxy service."""
    for lst in _haproxy_haproxycfg_secure(
        haproxy_password_list=haproxy_password_list,
        haproxy_username_list=haproxy_username_list,
        pytestconfig=pytestconfig,
        scale_factor=1,
        tmp_path_factory=tmp_path_factory,
    ):
        yield lst[0]


@pytest.fixture(scope="session")
def haproxy_haproxycfg_secure_list(
    haproxy_password_list: List[str],
    haproxy_username_list: List[str],
    pdhf_scale_factor: int,
    pytestconfig: "_pytest.config.Config",
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """Provides the location of the haproxy configuration file for the secure haproxy service."""
    yield from _haproxy_haproxycfg_secure(
        haproxy_password_list=haproxy_password_list,
        haproxy_username_list=haproxy_username_list,
        pytestconfig=pytestconfig,
        scale_factor=pdhf_scale_factor,
        tmp_path_factory=tmp_path_factory,
    )


def _haproxy_insecure(
    *,
    docker_compose_insecure_list: List[Path],
    docker_services: Services,
    haproxy_haproxycfg_insecure_list: List[Path],
    scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[HAProxyInsecure], None, None]:
    """Provides the endpoint of a local, insecure, haproxy."""
    cache_key = _haproxy_insecure.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        service_name = HAPROXY_SERVICE_PATTERN.format("insecure", i)
        tmp_path = tmp_path_factory.mktemp(__name__)

        # Create a secure haproxy service from the docker compose template ...
        path_docker_compose = tmp_path.joinpath(f"docker-compose-{i}.yml")
        template = Template(docker_compose_insecure_list[i].read_text("utf-8"))
        path_docker_compose.write_text(
            template.substitute(
                {
                    "CONTAINER_NAME": service_name,
                    # Note: Needed to correctly populate the embedded, consolidated, service template ...
                    "PATH_CERTIFICATE": "/dev/null",
                    "PATH_HAPROXYCFG": haproxy_haproxycfg_insecure_list[i],
                    "PATH_KEY": "/dev/null",
                }
            ),
            "utf-8",
        )

        LOGGER.debug("Starting insecure haproxy service [%d] ...", i)
        LOGGER.debug("  docker-compose : %s", path_docker_compose)
        LOGGER.debug("  service name   : %s", service_name)
        LOGGER.debug("  haproxycfg     : %s", haproxy_haproxycfg_insecure_list[i])

        check_server = partial(check_proxy, protocol="http")
        endpoint = start_service(
            docker_services,
            check_server=check_server,
            docker_compose=path_docker_compose,
            private_port=HAPROXY_PORT_INSECURE,
            service_name=service_name,
        )
        LOGGER.debug("Insecure haproxy endpoint [%d]: %s", i, endpoint)

        result.append(
            HAProxyInsecure(
                docker_compose=path_docker_compose,
                endpoint=endpoint,
                endpoint_name=f"{service_name}:{HAPROXY_PORT_INSECURE}",
                service_name=service_name,
            )
        )
    CACHE[cache_key] = result
    yield result


@pytest.fixture(scope="session")
def haproxy_insecure(
    docker_services: Services,
    haproxy_haproxycfg_insecure: Path,
    pdhf_docker_compose_insecure: Path,
    tmp_path_factory: TempPathFactory,
) -> Generator[HAProxyInsecure, None, None]:
    """Provides the endpoint of a local, insecure, haproxy."""
    for lst in _haproxy_insecure(
        docker_compose_insecure_list=[pdhf_docker_compose_insecure],
        docker_services=docker_services,
        haproxy_haproxycfg_insecure_list=[haproxy_haproxycfg_insecure],
        scale_factor=1,
        tmp_path_factory=tmp_path_factory,
    ):
        yield lst[0]


@pytest.fixture(scope="session")
def haproxy_insecure_list(
    docker_services: Services,
    haproxy_haproxycfg_insecure_list: List[Path],
    pdhf_docker_compose_insecure_list: List[Path],
    pdhf_scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[HAProxyInsecure], None, None]:
    """Provides the endpoint of a local, insecure, haproxy."""
    yield from _haproxy_insecure(
        docker_compose_insecure_list=pdhf_docker_compose_insecure_list,
        docker_services=docker_services,
        haproxy_haproxycfg_insecure_list=haproxy_haproxycfg_insecure_list,
        scale_factor=pdhf_scale_factor,
        tmp_path_factory=tmp_path_factory,
    )


def _haproxy_password(*, scale_factor: int) -> List[str]:
    """Provides the password to use for authentication to the secure haproxy service."""
    cache_key = _haproxy_password.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        result.append(f"pytest.password.{time()}")
        sleep(0.05)
    CACHE[cache_key] = result
    return result


@pytest.fixture(scope="session")
def haproxy_password() -> str:
    """Provides the password to use for authentication to the secure haproxy service."""
    return _haproxy_password(scale_factor=1)[0]


@pytest.fixture(scope="session")
def haproxy_password_list(pdhf_scale_factor: int) -> List[str]:
    """Provides the password to use for authentication to the secure haproxy service."""
    return _haproxy_password(scale_factor=pdhf_scale_factor)


def _haproxy_secure(
    *,
    docker_compose_secure_list: List[Path],
    docker_services: Services,
    haproxy_auth_header_list: List[Dict[str, str]],
    haproxy_cacerts_list: List[Path],
    haproxy_certs_list: List[HAProxyCerts],
    haproxy_haproxycfg_secure_list: List[Path],
    haproxy_password_list: List[str],
    haproxy_ssl_context_list: List[SSLContext],
    haproxy_username_list: List[str],
    scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[HAProxySecure], None, None]:
    """Provides the endpoint of a local, secure, haproxy."""
    cache_key = _haproxy_secure.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        service_name = HAPROXY_SERVICE_PATTERN.format("secure", i)
        tmp_path = tmp_path_factory.mktemp(__name__)

        # Create a secure haproxy service from the docker compose template ...
        path_docker_compose = tmp_path.joinpath(f"docker-compose-{i}.yml")
        template = Template(docker_compose_secure_list[i].read_text("utf-8"))
        path_docker_compose.write_text(
            template.substitute(
                {
                    "CONTAINER_NAME": service_name,
                    "PATH_CERTIFICATE": haproxy_certs_list[i].certificate,
                    "PATH_HAPROXYCFG": haproxy_haproxycfg_secure_list[i],
                    "PATH_KEY": haproxy_certs_list[i].private_key,
                }
            ),
            "utf-8",
        )

        LOGGER.debug("Starting secure haproxy service [%d] ...", i)
        LOGGER.debug("  docker-compose : %s", path_docker_compose)
        LOGGER.debug("  ca certificate : %s", haproxy_certs_list[i].ca_certificate)
        LOGGER.debug("  certificate    : %s", haproxy_certs_list[i].certificate)
        LOGGER.debug("  haproxycfg     : %s", haproxy_haproxycfg_secure_list[i])
        LOGGER.debug("  private key    : %s", haproxy_certs_list[i].private_key)
        LOGGER.debug("  password       : %s", haproxy_password_list[i])
        LOGGER.debug("  service name   : %s", service_name)
        LOGGER.debug("  username       : %s", haproxy_username_list[i])

        check_server = partial(
            check_proxy,
            auth_header=haproxy_auth_header_list[i],
            protocol="https",
            ssl_context=haproxy_ssl_context_list[i],
        )
        endpoint = start_service(
            docker_services,
            check_server=check_server,
            docker_compose=path_docker_compose,
            private_port=HAPROXY_PORT_SECURE,
            service_name=service_name,
        )
        LOGGER.debug("Secure haproxy endpoint [%d]: %s", i, endpoint)

        result.append(
            HAProxySecure(
                auth_header=haproxy_auth_header_list[i],
                cacerts=haproxy_cacerts_list[i],
                certs=haproxy_certs_list[i],
                docker_compose=path_docker_compose,
                endpoint=endpoint,
                endpoint_name=f"{service_name}:{HAPROXY_PORT_SECURE}",
                password=haproxy_password_list[i],
                service_name=service_name,
                ssl_context=haproxy_ssl_context_list[i],
                username=haproxy_username_list[i],
            )
        )
    CACHE[cache_key] = result
    yield result


@pytest.fixture(scope="session")
def haproxy_secure(
    docker_services: Services,
    haproxy_auth_header,
    haproxy_cacerts: Path,
    haproxy_certs: HAProxyCerts,
    haproxy_haproxycfg_secure: Path,
    haproxy_password: str,
    haproxy_ssl_context: SSLContext,
    haproxy_username: str,
    pdhf_docker_compose_secure: Path,
    tmp_path_factory: TempPathFactory,
) -> Generator[HAProxySecure, None, None]:
    """Provides the endpoint of a local, secure, haproxy."""
    for lst in _haproxy_secure(
        docker_compose_secure_list=[pdhf_docker_compose_secure],
        haproxy_auth_header_list=[haproxy_auth_header],
        haproxy_cacerts_list=[haproxy_cacerts],
        haproxy_certs_list=[haproxy_certs],
        haproxy_haproxycfg_secure_list=[haproxy_haproxycfg_secure],
        haproxy_password_list=[haproxy_password],
        haproxy_ssl_context_list=[haproxy_ssl_context],
        haproxy_username_list=[haproxy_username],
        docker_services=docker_services,
        scale_factor=1,
        tmp_path_factory=tmp_path_factory,
    ):
        yield lst[0]


@pytest.fixture(scope="session")
def haproxy_secure_list(
    docker_services: Services,
    haproxy_auth_header_list,
    haproxy_cacerts_list: List[Path],
    haproxy_certs_list: List[HAProxyCerts],
    haproxy_haproxycfg_secure_list: List[Path],
    haproxy_password_list: List[str],
    haproxy_ssl_context_list: List[SSLContext],
    haproxy_username_list: List[str],
    pdhf_docker_compose_secure_list: List[Path],
    pdhf_scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[HAProxySecure], None, None]:
    """Provides the endpoint of a local, secure, haproxy."""
    yield from _haproxy_secure(
        docker_compose_secure_list=pdhf_docker_compose_secure_list,
        haproxy_auth_header_list=haproxy_auth_header_list,
        haproxy_cacerts_list=haproxy_cacerts_list,
        haproxy_certs_list=haproxy_certs_list,
        haproxy_haproxycfg_secure_list=haproxy_haproxycfg_secure_list,
        haproxy_password_list=haproxy_password_list,
        haproxy_ssl_context_list=haproxy_ssl_context_list,
        haproxy_username_list=haproxy_username_list,
        docker_services=docker_services,
        scale_factor=pdhf_scale_factor,
        tmp_path_factory=tmp_path_factory,
    )


def _haproxy_ssl_context(
    *, haproxy_cacerts_list: List[Path], scale_factor: int
) -> List[SSLContext]:
    """
    Provides an SSLContext referencing the temporary CA certificate trust store that contains the certificate of the
    secure haproxy service.
    """
    cache_key = _haproxy_ssl_context.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        result.append(create_default_context(cafile=str(haproxy_cacerts_list[i])))
    CACHE[cache_key] = result
    return result


@pytest.fixture(scope="session")
def haproxy_ssl_context(haproxy_cacerts: Path) -> SSLContext:
    """
    Provides an SSLContext referencing the temporary CA certificate trust store that contains the certificate of the
    secure haproxy service.
    """
    return _haproxy_ssl_context(haproxy_cacerts_list=[haproxy_cacerts], scale_factor=1)[
        0
    ]


@pytest.fixture(scope="session")
def haproxy_ssl_context_list(
    haproxy_cacerts_list: List[Path],
    pdhf_scale_factor: int,
) -> List[SSLContext]:
    """
    Provides an SSLContext referencing the temporary CA certificate trust store that contains the certificate of the
    secure haproxy service.
    """
    return _haproxy_ssl_context(
        haproxy_cacerts_list=haproxy_cacerts_list,
        scale_factor=pdhf_scale_factor,
    )


def _haproxy_username(*, scale_factor: int) -> List[str]:
    """Retrieve the name of the user to use for authentication to the secure haproxy service."""
    cache_key = _haproxy_username.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        result.append(f"pytest.username.{time()}")
        sleep(0.05)
    CACHE[cache_key] = result
    return result


@pytest.fixture(scope="session")
def haproxy_username() -> str:
    """Retrieve the name of the user to use for authentication to the secure haproxy service."""
    return _haproxy_username(scale_factor=1)[0]


@pytest.fixture(scope="session")
def haproxy_username_list(
    pdhf_scale_factor: int,
) -> List[str]:
    """Retrieve the name of the user to use for authentication to the secure haproxy service."""
    return _haproxy_username(scale_factor=pdhf_scale_factor)


def _pdhf_docker_compose_insecure(
    *,
    docker_compose_files: List[str],
    scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """
    Provides the location of the docker-compose configuration file containing the insecure haproxy service.
    """
    cache_key = _pdhf_docker_compose_insecure.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        service_name = HAPROXY_SERVICE_PATTERN.format("insecure", i)
        chain = itertools.chain(
            get_docker_compose_user_defined(docker_compose_files, service_name),
            # TODO: lovely-docker-compose uses the file for teardown ...
            get_embedded_file(
                tmp_path_factory, delete_after=False, name="docker-compose.yml"
            ),
        )
        for path in chain:
            result.append(path)
            break
        else:
            LOGGER.warning("Unable to find docker compose for: %s", service_name)
            result.append("-unknown-")
    CACHE[cache_key] = result
    yield result


@pytest.fixture(scope="session")
def pdhf_docker_compose_insecure(
    docker_compose_files: List[str], tmp_path_factory: TempPathFactory
) -> Generator[Path, None, None]:
    """
    Provides the location of the docker-compose configuration file containing the insecure haproxy service.
    """
    for lst in _pdhf_docker_compose_insecure(
        docker_compose_files=docker_compose_files,
        scale_factor=1,
        tmp_path_factory=tmp_path_factory,
    ):
        yield lst[0]


@pytest.fixture(scope="session")
def pdhf_docker_compose_insecure_list(
    docker_compose_files: List[str],
    pdhf_scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """
    Provides the location of the docker-compose configuration file containing the insecure haproxy service.
    """
    yield from _pdhf_docker_compose_insecure(
        docker_compose_files=docker_compose_files,
        scale_factor=pdhf_scale_factor,
        tmp_path_factory=tmp_path_factory,
    )


def _pdhf_docker_compose_secure(
    *,
    docker_compose_files: List[str],
    scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """
    Provides the location of the templated docker-compose configuration file containing the secure haproxy
    service.
    """
    cache_key = _pdhf_docker_compose_secure.__name__
    result = CACHE.get(cache_key, [])
    for i in range(scale_factor):
        if i < len(result):
            continue

        service_name = HAPROXY_SERVICE_PATTERN.format("secure", i)
        chain = itertools.chain(
            get_docker_compose_user_defined(docker_compose_files, service_name),
            get_embedded_file(
                tmp_path_factory, delete_after=False, name="docker-compose.yml"
            ),
        )
        for path in chain:
            result.append(path)
            break
        else:
            LOGGER.warning("Unable to find docker compose for: %s", service_name)
            result.append("-unknown-")
    CACHE[cache_key] = result
    yield result


@pytest.fixture(scope="session")
def pdhf_docker_compose_secure(
    docker_compose_files: List[str], tmp_path_factory: TempPathFactory
) -> Generator[Path, None, None]:
    """
    Provides the location of the templated docker-compose configuration file containing the secure haproxy
    service.
    """
    for lst in _pdhf_docker_compose_secure(
        docker_compose_files=docker_compose_files,
        scale_factor=1,
        tmp_path_factory=tmp_path_factory,
    ):
        yield lst[0]


@pytest.fixture(scope="session")
def pdhf_docker_compose_secure_list(
    docker_compose_files: List[str],
    pdhf_scale_factor: int,
    tmp_path_factory: TempPathFactory,
) -> Generator[List[Path], None, None]:
    """
    Provides the location of the templated docker-compose configuration file containing the secure haproxy
    service.
    """
    yield from _pdhf_docker_compose_secure(
        docker_compose_files=docker_compose_files,
        scale_factor=pdhf_scale_factor,
        tmp_path_factory=tmp_path_factory,
    )


@pytest.fixture(scope="session")
def pdhf_scale_factor() -> int:
    """Provides the number enumerated instances to be instantiated."""
    return 1
