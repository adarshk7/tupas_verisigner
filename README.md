[![Build Status](https://api.travis-ci.org/adarshk7/tupas_verisigner.png)](https://api.travis-ci.org/adarshk7/tupas_verisigner)

# TUPAS Verisigner

## Introduction

This package can be used to:

* Receive a TUPAS request URL and parse it.
* Calculate the signature using a shared input secret and query params.
* Compare it to the signature in the URL.
* And, generate a response URL with new signature based on an shared output secret.


## Usage

```
from tupas_versigner import TupasVerisigner

signer = TupasVerisigner(
    input_secret,            # Shared input secret.
    output_secret,           # Shared output secret.
    base_output_url,         # Base URL for the response.
    error_url                # Error URL to return if signature verification fails.
    encoding='Windows-1252'  # Optional, default: 'Windows-1252'
)

signer.verify_and_sign_url(url)
```

For example,

```
from tupas_versigner import TupasVerisigner

signer = TupasVerisigner(
    'inputsecret',
    'outputsecret'
    'http://otherserver.com',
    'http://otherserver.com/error.html'
)

url = (
    'http://someserver.com/?B02K_VERS=0003&B02K_TIMESTMP=50020181017141433899056&'
    'B02K_IDNBR=2512408990&B02K_STAMP=20010125140015123456&B02K_CUSTNAME=FIRST%20'
    'LAST&B02K_KEYVERS=0001&B02K_ALG=03&B02K_CUSTID=9984&B02K_CUSTTYPE=02&B02K_MA'
    'C=EBA959A76B87AE8996849E7C0C08D4AC44B053183BE12C0DAC2AD0C86F9F2542'
)

signer.verify_and_sign_url(url)
```

> http://otherserver.com/?firstname=First&lastname=Last&hash= 4f6536ca2a23592d9037a4707bb44980b9bd2d4250fc1c833812068ccb000712


## Tests

`pip install -r requirements.txt`


### Unit tests

`pytest`


### Linting

`flake8 .`
`isort --recursive --diff . && isort --recursive --check-only .`
