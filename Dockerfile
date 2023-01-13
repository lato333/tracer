ARG BUILDER_IMAGE=debian:bullseye
#ARG BASE_IMAGE=alpine:3.14
ARG BASE_IMAGE=debian:bullseye
ARG BUILDPLATFORM=linux/amd64
ARG BUILDPLATFORM=linux/amd64

# Prepare and build gadget artifacts in a container
FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETARCH
# We need a cross compiler and libraries for TARGETARCH due to CGO.
RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make ca-certificates git && \
	echo 'deb http://deb.debian.org/debian bullseye-backports main' >> /etc/apt/sources.list && \
	apt-get update && \
	apt-get install -y golang-1.18 libelf-dev pkg-config libseccomp-dev && \
	ln -s /usr/lib/go-1.18/bin/go /bin/go 

RUN mkdir -p /opt/tracer/
WORKDIR /opt/tracer/
COPY go.mod go.sum /opt/tracer/
COPY tracer.go /opt/tracer/

RUN go build .

# Main gadget image
FROM ${BASE_IMAGE}

COPY --from=builder /opt/tracer/tracer /bin/tracer
RUN mkdir -p /etc/tracer/
COPY tracer.yml /etc/tracer/

# Mitigate https://github.com/kubernetes/kubernetes/issues/106962.
RUN rm -f /var/run

ENTRYPOINT ["/bin/tracer","-config","/etc/tracer/tracer.yml"]
#ENTRYPOINT ["sleep","infinity"]
