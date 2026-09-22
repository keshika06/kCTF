# Spec Ops -- kCTF pwn challenge Dockerfile
# Same shape as the other pwn builds in this set, except this binary is
# dynamically linked on purpose (no -static): the whole point of the
# challenge is leaking a real libc address, so libc.so.6 has to actually
# be there to leak from.

FROM ubuntu:24.04 AS chroot

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc make && \
    rm -rf /var/lib/apt/lists/*

RUN /usr/sbin/userdel -r ubuntu && /usr/sbin/useradd --no-create-home -u 1000 user

COPY flag /
RUN chmod 744 /flag

COPY chal.c Makefile /home/user/
WORKDIR /home/user
RUN make && rm chal.c Makefile

FROM gcr.io/kctf-docker/challenge@sha256:738102f3144fd9cd0858b44d4f30f8f94bc73881be44aa8a2d13eee2099b9375

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/chal"
