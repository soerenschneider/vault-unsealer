# vault-unsealer
[![Go Report Card](https://goreportcard.com/badge/github.com/soerenschneider/vault-unsealer)](https://goreportcard.com/report/github.com/soerenschneider/vault-unsealer)
![test-workflow](https://github.com/soerenschneider/vault-unsealer/actions/workflows/test.yaml/badge.svg)
![release-workflow](https://github.com/soerenschneider/vault-unsealer/actions/workflows/release.yaml/badge.svg)
![golangci-lint-workflow](https://github.com/soerenschneider/vault-unsealer/actions/workflows/golangci-lint.yaml/badge.svg)

Automatically unseals configured Vault instances using a push mechanism.

## Key Features

🔐 Retrieve Vault's unseal key from Vault's KV2 or transit secret engine<br/>
🛂 Authenticate against Vault using AppRole, (explicit) token or _implicit_ auth<br/>
🔭 Robust automation through observability<br/>

## FAQ

**Q:** Why would I need auto-unsealing?<br/>
**A:** I'm trying to push OS-, container image- and Vault-updates itself rather aggressively, therefore I'm not patching any machines manually, but automatically (see [conditional-reboot](https://github.com/soerenschneider/conditional-reboot)). Hence, I need a mechanism that unseals preconfigured Vault instances automatically without human intervention.
<hr/>

**Q:** Ok, but why not using auto-unsealing using [AWS KMS](https://developer.hashicorp.com/vault/tutorials/auto-unseal/autounseal-aws-kms) / [Azure Key Vault](https://developer.hashicorp.com/vault/tutorials/auto-unseal/autounseal-azure-keyvault) / [GCP KMS](https://developer.hashicorp.com/vault/tutorials/auto-unseal/autounseal-gcp-kms)?<br/>
**A:** If your Vault clusters / instances do not run one of the specified cloud providers (like mine), you'll have to issue and deal with access keys to said platforms: distribute them secretly, keep them safe and rotate them frequently. Vault-unsealer [reads the unseal key from Vault itself](#how-does-it-work) (make sure it's well protected!) as I've written enough tooling that helps me keep my Vault credentials safe and rotate them both frequently and automatically (e.g. [vault-approle-cli](https://github.com/soerenschneider/scripts/blob/main/vault/vault-approle-cli.py) or [vault-mfa](https://github.com/soerenschneider/scripts/blob/main/vault/vault_mfa.py)).
<hr/>

**Q:** Why not using auto-unsealing using [Vault Transit](https://developer.hashicorp.com/vault/tutorials/auto-unseal/autounseal-transit)?<br/>
**A:** I did not want to manage another cluster / production instances of Hashicorp Vault even though I built some tooling around it that keeps maintenance low.
<hr/>

**Q:** Do only three real question justify an own FAQ section?<br/>
**A:** Probably not, but here we are.
<hr/>

## Installation

### Docker / Podman
````shell
$ git clone https://github.com/soerenschneider/vault-unsealer.git
$ cd vault-unsealer
$ docker run -v $(pwd)/contrib:/config ghcr.io/soerenschneider/vault-unsealer:main -conf /config/example-config.json
````

### Binaries
Head over to the [prebuilt binaries](https://github.com/soerenschneider/vault-unsealer/releases) and download the correct binary for your system.
Use the example [systemd service file](contrib/vault-unsealer.service) to run it at boot.

### From Source
As a prerequesite, you need to have [Golang SDK](https://go.dev/dl/) installed. After that, you can install vault-unsealer from source by invoking:
```text
$ go install github.com/soerenschneider/vault-unsealer@latest
```

## Configuration

An example configuration can be found [here](contrib/example-config-static.json). Note that this example is oversimplified and not secure.
Head over to the [configuration section](docs/configuration.md) to see more details.


## Observability

Check [here](docs/metrics.md)

## How does it work?
![unsealer](docs/vault-unsealer.svg)

## CHANGELOG
The changelog can be found [here](CHANGELOG.md)