FROM debian:bookworm-slim

USER root

# Install basic tools
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get --yes update
RUN apt-get --yes install locales strace libconfig9
RUN apt-get --yes clean
RUN echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen && locale-gen
RUN mkdir -p /tmp/elogd_test
