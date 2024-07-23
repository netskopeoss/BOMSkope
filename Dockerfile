FROM ubuntu:24.04

# Prevent interactive dialogue during package installation
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-setuptools \
    python3-venv \
    nginx \
    libmagic1 \
    file \
    libicu-dev \
    curl 


WORKDIR /
RUN mkdir -p app
RUN mkdir -p /app/temp

COPY app /app/

WORKDIR /app

RUN curl -k -L -o /app/cyclonedx-linux-x64 https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.25.1/cyclonedx-linux-x64

# Mark the file as executable
RUN chmod +x /app/cyclonedx-linux-x64

COPY files/app.service /etc/systemd/system

COPY files/app /etc/nginx/sites-available

RUN ln -s /etc/nginx/sites-available/app /etc/nginx/sites-enabled

COPY files/nginx-cert.crt /etc/ssl/certs
COPY files/nginx-cert.key /etc/ssl/private

COPY files/self-signed.conf /etc/nginx/snippets
COPY files/ssl-params.conf /etc/nginx/snippets

COPY files/nginx.conf /etc/nginx

RUN openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

RUN chown -R root:www-data /app

COPY files/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 443

ENTRYPOINT ["/entrypoint.sh"]