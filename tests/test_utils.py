#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""pytest fixture tests."""

import logging

from pathlib import Path
from typing import List

from OpenSSL import crypto
from _pytest.tmpdir import TempPathFactory

from pytest_docker_haproxy_fixtures import (
    generate_cacerts,
    generate_haproxycfg,
    generate_keypair,
    get_docker_compose_user_defined,
    get_embedded_file,
    get_user_defined_file,
    HAPROXY_SERVICE_PATTERN,
)

LOGGER = logging.getLogger(__name__)


# TODO: test_check_url_secure


def test_generate_cacerts(tmp_path_factory: TempPathFactory, tmp_path: Path):
    """Test that a temporary cacerts file can be generated."""
    certificate = "MY CERTIFICATE VALUE"
    path = tmp_path.joinpath("certificate")
    path.write_text(certificate, "utf-8")
    path_last = None
    for path in generate_cacerts(tmp_path_factory, certificate=path):
        assert path.exists()
        content = path.read_text("utf-8")
        assert certificate in content
        path_last = path
    assert path_last
    assert not path_last.exists()


def test_generate_haproxycfg(tmp_path_factory: TempPathFactory):
    """Test that a temporary haproxy configuration file can be generated."""
    username = "myusername"
    password = "mypassword"
    path_last = None
    for path in generate_haproxycfg(
        tmp_path_factory, password=password, username=username
    ):
        assert path.exists()
        content = path.read_text("utf-8")
        assert username in content
        assert password in content
        path_last = path
    assert path_last
    assert not path_last.exists()


def test_generate_keypair():
    """Test that a keypair can be generated."""
    keypair = generate_keypair()
    assert keypair.ca_certificate
    assert keypair.ca_private_key
    assert keypair.certificate
    assert keypair.private_key

    x509_store = crypto.X509Store()
    ca_certificate = crypto.load_certificate(
        crypto.FILETYPE_PEM, keypair.ca_certificate
    )
    x509_store.add_cert(ca_certificate)

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, keypair.certificate)
    x509_store_context = crypto.X509StoreContext(x509_store, certificate)
    x509_store_context.verify_certificate()


def test_get_docker_compose_user_defined(docker_compose_files: List[str]):
    """Tests that the user defined check fails here."""

    service_name = HAPROXY_SERVICE_PATTERN.format("insecure", 0)
    for _ in get_docker_compose_user_defined(docker_compose_files, service_name):
        assert False
    service_name = HAPROXY_SERVICE_PATTERN.format("secure", 0)
    for _ in get_docker_compose_user_defined(docker_compose_files, service_name):
        assert False


def test_get_embedded_file(tmp_path_factory: TempPathFactory):
    """Test that an embedded file can be replicated to a temporary file."""
    path_last = None
    for path in get_embedded_file(tmp_path_factory, name="docker-compose.yml"):
        assert path.exists()
        content = path.read_text("utf-8")
        assert "proxy" in content
        path_last = path
    assert path_last
    assert not path_last.exists()


def test_get_user_defined_file(pytestconfig: "_pytest.config.Config"):
    """Tests that the user defined check fails here."""

    for _ in get_user_defined_file(pytestconfig, "does_not_exist"):
        assert False


# TODO: test_start_service
