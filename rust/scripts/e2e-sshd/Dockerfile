FROM alpine:3.21
RUN apk add --no-cache openssh openssh-sftp-server bash tar && \
    ssh-keygen -A && \
    adduser -D -s /bin/bash tester && echo "tester:testpass" | chpasswd && \
    mkdir -p /home/tester/.ssh && chmod 700 /home/tester/.ssh && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/; s/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/; s/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/; s/^#\?GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config && \
    echo "Subsystem sftp /usr/lib/ssh/sftp-server" >> /etc/ssh/sshd_config
COPY e2e_key.pub /home/tester/.ssh/authorized_keys
RUN chown -R tester:tester /home/tester/.ssh && chmod 600 /home/tester/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
