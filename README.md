# Keylib

[![CircleCI](https://img.shields.io/circleci/project/blockstack/keylib-py/master.svg)](https://circleci.com/gh/blockstack/keylib-py/tree/master)
[![PyPI](https://img.shields.io/pypi/v/keylib.svg)](https://pypi.python.org/pypi/keylib/)
[![PyPI](https://img.shields.io/pypi/dm/keylib.svg)](https://pypi.python.org/pypi/keylib/)
[![PyPI](https://img.shields.io/pypi/l/keylib.svg)](https://github.com/namesystem/keylib/blob/master/LICENSE)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

### Installation

```bash
$ pip install keylib
```

### Usage

#### Private Keys

```python
>>> from keylib import ECPrivateKey
>>> private_key = ECPrivateKey()
>>> private_key.to_hex()
'6c59ab3cfea30a6fe9c9f6b06f956d34d946c1159842f44ce391c1d965cee4b601'
>>> private_key.to_wif()
'KzrL5BXNt9nFJmVdxqDNWkPsNJhsE6MdcxULCFZRV5w58pYg6Eiz'
>>> private_key_2 = ECPrivateKey(private_key.to_hex())
>>> print private_key.to_wif() == private_key_2.to_wif()
True
```

#### Public Keys

```python
>>> from keylib import ECPublicKey
>>> public_key = private_key.public_key()
>>> public_key.to_hex()
'03019979ec442e61ace8d47c6a344d791cee12d4e7bbde05fa91a62c0cda51c834'
>>> public_key_2 = ECPublicKey(public_key.to_hex())
>>> print public_key.to_hex() == public_key_2.to_hex()
True
```

#### Addresses

```python
>>> public_key.address()
'12WDrxysCBDtVxaP1n4HHj8BLqqqfaqANd'
>>> public_key.hash160()
'107eecc5868111ba06e6bd9309b2db90c555cb6e'
```
