# Identity Instrument

Identity Instrument is a simple service that runs inside a secure TEE (Trusted Execution Environment) enclave and maps Web2 credentials (email, social) to Web3 EOA wallets. It powers the authentication for [Sequence Ecosystem Wallets](https://docs.sequence.xyz/solutions/wallets/ecosystem/overview).

## Enclave verification

Switch to the version currently running in production:

```
git checkout $(curl --silent https://waas.sequence.app/status | jq -r .ver)
```

Ensure the version matches what you expect. E.g. [compare with the published releases](https://github.com/0xsequence/identity-instrument/releases).

Then, run the verification script:

```
./verify.sh
```

You can configure it by passing environment variables:

- `ENV` - `prod` or `dev` (identifies which file in `etc/` is used for building the EIF)
- `URL` - where to fetch the deployed service's attestation from
- `VERSION` - the version to be included in the EIF (default: current git tag)
- `PCR0` - the expected PCR0, overriding the PCR0 from the build (e.g. all dev enclaves will report `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`)

## Local development

Copy sample `.env.sample` to `.env`. This sample environment config enables `OTP` and a generic `IDToken` authentication flows. To make Google/Apple auth work, edit the file with your Google/Apple client details.

Run the service with all dependencies:

```
make up
```

(Please note that this requires Docker installed and running.)

This starts the following containers:

- `nitro`: Identity Instrument itself
- `ingress`: a basic ingress proxy that handles CORS and decorates requests with required HTTP headers
- `localstack`: local AWS services (DynamoDB, KMS, SES), see https://www.localstack.cloud/
- `builder-mock`: a mock [Sequence Builder](https://sequence.build/) service, used by Identity Instrument for email message generation

All data, including signers, is ephemeral and lost when the containers stop. Make sure you don't depend on stable EOA addresses.

### View sent emails

All OTP emails sent by Identity Instrument are stored by `localstack`. Run the following command to retrieve them:

```
curl --silent 'localhost.localstack.cloud:4566/_aws/ses?email=noreply@local.auth.sequence.app' | jq .
```

