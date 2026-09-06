# lab/attacker/Dockerfile
#
# A minimal Kali-adjacent (Alpine-based, since Alpine ships every tool the
# lab needs and stays tiny) offensive toolkit container used to fire
# synthetic attacks at the "victim" service over the lab's private Docker
# network. Never used, referenced, or shipped anywhere near VANGUARD's own
# production build/deploy path -- purely a test fixture confined to lab/.
FROM alpine:3.20

RUN apk add --no-cache \
        bash \
        curl \
        nmap \
        nmap-scripts \
        hydra \
        openssh-client \
        jq \
        coreutils

WORKDIR /lab
COPY lab/run-tests.sh /lab/run-tests.sh
RUN chmod +x /lab/run-tests.sh

ENTRYPOINT ["/bin/bash"]
