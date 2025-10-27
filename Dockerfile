#
# Enclave base image
#
FROM golang:1.25.3-alpine3.22@sha256:aee43c3ccbf24fdffb7295693b6e33b21e01baec1b2a55acc351fde345e9ec34 AS base

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


FROM ghcr.io/0xsequence/eiffel:v0.4.0@sha256:0e91d93aa3fba312add1ca812b9b1051008fc34283f09844d8949d1c6fc1a25b

ARG ENV_ARG=dev

RUN mkdir /workspace

ADD ./.eiffel/ /workspace/
ADD ./etc/identity.${ENV_ARG}.conf /workspace/identity.conf
COPY --from=builder /go/src/github.com/0xsequence/identity-instrument/bin/identity /workspace/identity

CMD ["nitro"]
