FROM golang:1.16-alpine3.15 AS build

# Set destination for COPY
WORKDIR /

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
COPY go.mod .
COPY go.sum .
COPY *.go .
COPY config /config
COPY proxy /proxy
COPY router /router
COPY services /services

RUN go env -w GOPROXY=https://goproxy.cn
RUN go mod download

# Build
RUN go build -o /gremlinproxy

FROM alpine:3.15

WORKDIR /

COPY --from=build /gremlinproxy /gremlinproxy
