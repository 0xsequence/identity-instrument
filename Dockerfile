#
# Enclave base image
#
FROM golang:1.23.5-alpine3.21@sha256:47d337594bd9e667d35514b241569f95fb6d95727c24b19468813d596d5ae596 AS base

RUN apk add make bash

#
# Ingress proxy
#
FROM base AS ingress

WORKDIR /go/src/github.com/0xsequence/seqv3-nitro

ADD ./ ./

CMD ["make", "run-ingress-proxy"]

#
# Enclave pre-image
#
FROM base AS builder

WORKDIR /go/src/github.com/0xsequence/seqv3-nitro

ADD ./ ./

ARG VERSION

RUN make VERSION=${VERSION} build

#
# Enclave dev image
#
FROM base AS dev

WORKDIR /go/src/github.com/0xsequence/seqv3-nitro

ENV CONFIG=./etc/nitro.conf

CMD ["make", "run"]


FROM ghcr.io/0xsequence/eiffel:v0.3.1@sha256:c0c0bf7144a6a25b00bf78e7d5cb632afae8b45f8b82ff38016fa8c61854a104

ARG ENV_ARG=dev

RUN mkdir /workspace

ADD ./.eiffel/ /workspace/
ADD ./etc/nitro.${ENV_ARG}.conf /workspace/nitro.conf
COPY --from=builder /go/src/github.com/0xsequence/seqv3-nitro/bin/nitro /workspace/nitro

CMD ["nitro"]
