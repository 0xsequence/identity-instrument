#
# Enclave base image
#
FROM golang:1.26.10-alpine3.23@sha256:a07f231c19b03e6106cf442f02a5bcf262147e744d15b7b5e4b6d81d420c70a0 AS base

RUN apk add make bash

#
# Enclave & ingress proxy pre-image
#
FROM base AS builder

WORKDIR /go/src/github.com/0xsequence/identity-instrument

ADD ./ ./

ARG VERSION

RUN make VERSION=${VERSION} build

#
# Ingress proxy dev image
#
FROM base AS ingress-dev

WORKDIR /go/src/github.com/0xsequence/identity-instrument

CMD ["make", "run-ingress-proxy"]

#
# Builder mock dev image
#
FROM base AS builder-mock-dev

WORKDIR /go/src/github.com/0xsequence/identity-instrument

CMD ["make", "run-builder-mock"]

#
# Enclave dev image
#
FROM base AS dev

WORKDIR /go/src/github.com/0xsequence/identity-instrument

ENV CONFIG=./etc/nitro.conf

CMD ["make", "run"]


FROM ghcr.io/0xsequence/eiffel:v0.6.0@sha256:c97b24f6fda022b785e5f86d94ae0b0b4aec8069d1c077dcd563027c20e6238d

ARG ENV_ARG=dev

RUN mkdir /workspace

ADD ./.eiffel/ /workspace/
ADD ./etc/identity.${ENV_ARG}.conf /workspace/identity.conf
COPY --from=builder /go/src/github.com/0xsequence/identity-instrument/bin/identity /workspace/identity

CMD ["nitro"]
