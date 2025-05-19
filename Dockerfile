#
# Enclave base image
#
FROM golang:1.23.5-alpine3.21@sha256:47d337594bd9e667d35514b241569f95fb6d95727c24b19468813d596d5ae596 AS base

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


FROM ghcr.io/0xsequence/eiffel:v0.3.1@sha256:c0c0bf7144a6a25b00bf78e7d5cb632afae8b45f8b82ff38016fa8c61854a104

ARG ENV_ARG=dev

RUN mkdir /workspace

ADD ./.eiffel/ /workspace/
ADD ./etc/identity.${ENV_ARG}.conf /workspace/identity.conf
COPY --from=builder /go/src/github.com/0xsequence/identity-instrument/bin/identity /workspace/identity

CMD ["nitro"]
