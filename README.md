# sts

An OIDC based token issuer

## Installation

On MacOS you can install or upgrade to the latest released version with Homebrew:
```sh
$ brew install dep
$ brew upgrade dep
```

On other platforms you can use the `_install.sh_` script:

```sh
$ curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
```

Then clone the repository:
```sh
$ git clone <repository>
```

Run `dep` and enjoy:
```sh
$ dep ensure
```

Prepare the envs :
```sh
STS_PORT=<port> (Default: 9021)
STS_EVA_URL=<eva_url>
STS_ISSUER_URL=<issuer_url>
STS_ISSUER_CLIENT_ID=<issuer_client_id>
STS_ISSUER_CLIENT_SECRET=<issuer_client_secret>
STS_LOG_LEVEL=<debug/info/warn/error>

export STS_PORT
export STS_EVA_URL
export STS_ISSUER_URL
export STS_ISSUER_CLIENT_ID
export STS_ISSUER_CLIENT_SECRET
export STS_LOG_LEVEL
```
