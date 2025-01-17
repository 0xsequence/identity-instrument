#
# Enclave base image
#
FROM golang:1.22.8-alpine3.19@sha256:fe5bea2e1ab3ffebe0267393fea88fcb197e2dbbb1e2dbabeec6dd9ccb0e1871 AS base

RUN apk add make bash

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
