# pytest-docker-haproxy-fixtures

## Overview

Pytest fixtures to instantiate and utilize local haproxy docker containers, using [lovely-pytest-docker](https://pypi.org/project/lovely-pytest-docker) and [docker-py](https://pypi.org/project/docker-py), for testing.

## Getting Started

Update <tt>setup.py</tt> to include:

```python
from distutils.core import setup

setup(
	tests_require=["pytest-docker-haproxy-fixtures"]
)
```

All fixtures should be automatically included via the <tt>pytest11</tt> entry point.
```python
import requests
import pytest
from pytest_docker_haproxy_fixtures import HAProxyInsecure, HAProxySecure  # Optional, for typing

def test_haproxy_secure(haproxy_secure: HAProxySecure):
    response = requests.head(f"https://{haproxy_secure.endpoint}/",
        headers=haproxy_secure.auth_header,
        verify=str(haproxy_secure.cacerts),
    )
    assert response.status_code == 200

def test_haproxy_insecure(haproxy_insecure: HAProxyInsecure):
    response = requests.head(f"http://{haproxy_insecure.endpoint}/")
    assert response.status_code == 200
```

The `push_image` mark can optionally be added to stage images in the haproxy prior to testing. See [Markers](#markers) for details.
## Compatibility

* Tested with python 3.8

## Installation
### From [pypi.org](https://pypi.org/project/pytest-docker-haproxy-fixtures/)

```
$ pip install pytest_docker_haproxy_fixtures
```

### From source code

```bash
$ git clone https://github.com/crashvb/pytest-docker-haproxy-fixtures
$ cd pytest-docker-haproxy-fixtures
$ virtualenv env
$ source env/bin/activate
$ python -m pip install --editable .[dev]
```

## <a name="fixtures"></a>Fixtures

### <a name="haproxy_auth_header"></a> haproxy_auth_header

Retrieves an HTTP basic authentication header that is populated with credentials that can access the secure haproxy service. The credentials are retrieved from the [haproxy_password](#haproxy_password) and [haproxy_username](#haproxy_username) fixtures. This fixture is used to replicate docker images into the secure haproxy service.

### <a name="haproxy_cacerts"></a> haproxy_cacerts

Locates a user-defined CA trust store (<tt>tests/cacerts</tt>) to use to verify connections to the secure haproxy service. If one cannot be located, a temporary trust store is created containing certificates from <tt>certifi</tt> and the [haproxy_certs](#haproxy_certs) fixture. This fixture is used to instantiate the secure haproxy service.

### <a name="haproxy_certs"></a> haproxy_certs

Returns the paths of the self-signed certificate authority certificate, certificate, and private key that are used by the secure haproxy service. This fixture is used to instantiate the secure haproxy service.

#### NamedTuple Fields

The following fields are defined in the tuple provided by this fixture:

* **ca_certificate** - Path to the self-signed certificate authority certificate.
* **ca_private_key** - Path to the self-signed certificate authority private key.
* **certificate** - Path to the certificate.
* **private_key** - Path to the private key.

Typing is provided by `pytest_docker_haproxy_fixtures.HAProxyCerts`.

### <a name="haproxy_haproxycfg_insecure"></a> haproxy_haproxycfg_insecure

Provides the path to an insecure haproxy.cfg file that is used by the insecure haproxy service. If a user-defined haproxy.cfg file (<tt>tests/haproxy.insecure.cfg</tt>) can be located, it is used. Otherwise, an embedded configuration is copied to a temporary location and returned. This fixture is used to instantiate the insecure haproxy service.

### <a name="haproxy_haproxycfg_secure"></a> haproxy_haproxycfg_secure

Provides the path to a secure haproxy.cfg file that is used by the secure haproxy service. If a user-defined haproxy.cfg file (<tt>tests/haproxy.secure.cfg</tt>) can be located, it is used. Otherwise, an embedded configuration is copied to a temporary location and returned. This fixture is used to instantiate the secure haproxy service. The configuration will be treated as a template; the <tt>$PASSWORD</tt> and <tt>$USERNAME</tt> tokens will be populated with values provided by the [haproxy_password](#haproxy_password) and [haproxy_username](#haproxy_username) fixtures, as appropriate.

### <a name="haproxy_insecure"></a> haproxy_insecure

Configures and instantiates a haproxy service without TLS or authentication.

```python
import requests
from pytest_docker_haproxy_fixtures import HAProxyInsecure  # Optional, for typing

def test_haproxy_insecure(haproxy_insecure: HAProxyInsecure):
    response = requests.head(f"http://{haproxy_insecure.endpoint}/")
    assert response.status_code == 200
```

#### NamedTuple Fields

The following fields are defined in the tuple provided by this fixture:

* **docker_compose** - Path to the fully instantiated docker-compose configuration.
* **endpoint** - Endpoint of the insecure haproxy service.
* **endpoint_name** - Endpoint of the insecure haproxy service, by server name.
* **service_name** - Name of the service within the docker-compose configuration.

Typing is provided by `pytest_docker_haproxy_fixtures.HAProxyInsecure`.

### <a name="haproxy_password"></a> haproxy_password

Provides a generated password to use for authentication to the secure haproxy service. This fixture is used to replicate docker images into the secure haproxy service.

### <a name="haproxy_secure"></a> haproxy_secure

Configures and instantiates a TLS enabled haproxy service with HTTP basic authorization.

```python
import requests
from pytest_docker_haproxy_fixtures import HAProxySecure  # Optional, for typing

def test_haproxy_secure(haproxy_secure: HAProxySecure):
    response = requests.head(
        f"https://{haproxy_secure.endpoint}/",
        headers=haproxy_secure.auth_header,
        verify=str(haproxy_secure.cacerts),
    )
    assert response.status_code == 200
```

#### NamedTuple Fields

The following fields are defined in the tuple provided by this fixture:

* **auth_header** - from [haproxy_auth_header](#haproxy_auth_header).
* **cacerts** - from [haproxy_cacerts](#haproxy_cacerts).
* **certs** - from [haproxy_certs](#haproxy_certs).
* **docker_compose** - Path to the fully instantiated docker-compose configuration.
* **endpoint** - Endpoint of the secure haproxy service.
* **endpoint_name** - Endpoint of the secure haproxy service, by server name.
* **password** - from [haproxy_password](#haproxy_password).
* **service_name** - Name of the service within the docker-compose configuration.
* **ssl_context** - from [haproxy_ssl_context](#haproxy_ssl_context).
* **username** - from [haproxy_username](#haproxy_username).

Typing is provided by `pytest_docker_haproxy_fixtures.HAProxySecure`.

### <a name="haproxy_ssl_context"></a> haproxy_ssl_context

Provides an SSL context containing the CA trust store from the  [haproxy_cacerts](#haproxy_cacerts) fixture. This fixture is used to instantiate the secure haproxy service.

### <a name="haproxy_username"></a> haproxy_username

Provides a generated username to use for authentication to the secure haproxy service. This fixture is used to replicate docker images into the secure haproxy service.

### <a name="pdhf_docker_compose_insecure"></a> pdhf_docker_compose_insecure

This fixture uses the `docker_compose_files` fixture to locate a user-defined docker-compose configuration file (typically <tt>tests/docker-compose.yml</tt>) that contains the <tt>pytest-docker-haproxy-insecure</tt> service. If one cannot be located, an embedded configuration is copied to a temporary location and returned. This fixture is used to instantiate the insecure haproxy service. The configuration will be treated as a template; the <tt>$PATH_HAPROXYCFG</tt> token will be populated with the absolute path provided by the [haproxy_haproxycfg](#haproxy_haproxycfg) fixture.

### <a name="pdhf_docker_compose_secure"></a> pdhf_docker_compose_secure

This fixture uses the `docker_compose_files` fixture to locate a user-defined docker-compose configuration file (typically <tt>tests/docker-compose.yml</tt>) that contains the <tt>pytest-docker-haproxy-secure</tt> service. If one cannot be located, an embedded configuration is copied to a temporary location and returned. This fixture is used to instantiate the secure haproxy service. The configuration will be treated as a template; the <tt>$PATH_CERTIFICATE</tt>, <tt>$PATH_HAPROXYCFG</tt>, and <tt>$PATH_KEY</tt> tokens will be populated with the absolute paths provided by the [haproxy_certs](#haproxy_certs) and [haproxy_haproxycfg](#haproxy_haproxycfg) fixtures, as appropriate.

## <a name="enumerated_fixtures"></a>Enumerated Fixtures

It is possible to instantiate multiple haproxy instances using the corresponding enumerated fixtures. All [fixtures](#fixtures) listed above have _*_list_ (e.g. `haproxy_secure` -> `haproxy_secure_list`) versions that will return enumerated lists of corresponding data type.

For example:

```python
import requests
from typing import List  # Optional, for typing
from pytest_docker_haproxy_fixtures import HAProxySecure  # Optional, for typing

def test_haproxy_secure_list(haproxy_secure_list: List[HAProxySecure]):
    for haproxy_secure in haproxy_secure_list:
        response = requests.head(
            f"https://{haproxy_secure.endpoint}/",
            headers=haproxy_secure.auth_header,
            verify=str(haproxy_secure.cacerts),
        )
        assert response.status_code == 200
```

It is possible to use both singular and enumerated fixtures within the same test context; however, the same values will be returned for the singular fixture as the first enumerated list value (i.e. haproxy_secure == haproxy_secure_list[0]). To avoid complications with lower layers, mainly docker-compose, and to allow for this interchangeability, caching is used internally.

By default, the scale factor of the enumerated instances is set to one (n=1). This value can be changed by overriding the `pdhf_scale_factor` fixture, as follows:

```python
import pytest

@pytest.fixture(scope="session")
def pdhf_scale_factor() -> int:
    return 4
```

This fixture will be used to scale both the insecure and secure docker registries.

## <a name="limitations"></a>Limitations

1. All the fixtures provided by this package are <tt>session</tt> scoped; and will only be executed once per test execution.
2. At most 10 insecure and 10 secure haproxy instances are supported using the embedded docker compose.

## Development

[Source Control](https://github.com/crashvb/pytest-docker-haproxy-fixtures)
