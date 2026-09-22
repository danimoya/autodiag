# Oracle Database Free (23ai) with an unprivileged sshd, to simulate a database node
# reachable by key-based SSH as the oracle user (the AutoDiag data path).
ARG BASE_IMAGE=container-registry.oracle.com/database/free:latest
FROM ${BASE_IMAGE}

USER root
# Regional OCI yum mirrors may be IPv6-only or unreachable; use the global mirror over IPv4.
RUN echo "ip_resolve=4" >> /etc/dnf/dnf.conf \
    && { [ -f /etc/dnf/vars/ociregion ] && : > /etc/dnf/vars/ociregion || true; } \
    && sed -i -E 's#yum-[a-z]+-[a-z]+-[0-9]+\.oracle\.com#yum.oracle.com#g' /etc/yum.repos.d/*.repo \
    && if command -v dnf >/dev/null 2>&1; then \
        dnf -y install openssh-server openssh-clients procps-ng && dnf clean all; \
    else \
        microdnf -y install openssh-server openssh-clients procps-ng && microdnf clean all; \
    fi \
    && mkdir -p /home/oracle/sshd /home/oracle/.ssh /autodiag \
    && chown -R oracle:oinstall /home/oracle /autodiag \
    && chmod 755 /home/oracle && chmod 700 /home/oracle/.ssh /home/oracle/sshd

COPY --chown=oracle:oinstall sshd/sshd_config /home/oracle/sshd_config
COPY --chown=oracle:oinstall sshd/01_sshd.sh /opt/oracle/scripts/startup/01_sshd.sh
COPY --chown=oracle:oinstall sshd/02_autodiag_setup.sh /opt/oracle/scripts/startup/02_autodiag_setup.sh
COPY --chown=oracle:oinstall setup/01_users.sh /opt/oracle/scripts/setup/01_users.sh
COPY --chown=oracle:oinstall setup/sql/ /opt/oracle/scripts/setup/sql/
RUN chmod 755 /opt/oracle/scripts/startup/*.sh /opt/oracle/scripts/setup/01_users.sh \
    && chmod 644 /home/oracle/sshd_config

USER oracle
EXPOSE 1521 2222
