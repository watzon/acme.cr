# ACME Example Servers

This directory contains proof-of-concept applications that demonstrate how to use `acme.cr` to automatically provision an SSL certificate and serve a secure webpage.

## Examples

### 1. Easy Mode (`server-easy.cr`)
Uses the high-level `Acme::Manager` to handle everything with minimal code. This is recommended for most users.

### 2. Full Mode (`server-full.cr`)
Uses the low-level `Acme::Client` and manual orchestration. This shows exactly how the ACME protocol flow works under the hood.

## Prerequisites

1.  **Public Server:** You need a server that is reachable from the internet (e.g., a VPS).
2.  **Domain Name:** You need a domain name (e.g., `example.com`) pointing to your server's IP address.
3.  **Root Privileges:** The server needs to bind to ports 80 and 443, which usually requires root/sudo.

## Usage

1.  Build the examples:
    ```bash
    crystal build examples/server-easy.cr -o server-easy
    crystal build examples/server-full.cr -o server-full
    ```

2.  Run the server (replace with your domain and email):
    ```bash
    sudo ./server-easy -d example.com -e admin@example.com
    ```

    By default, it uses the **Let's Encrypt Staging** environment. This is good for testing but the certificate won't be trusted by browsers.

3.  To use the **Production** environment (trusted certificate):
    ```bash
    sudo ./server-easy -d example.com -e admin@example.com --prod
    ```

## How it works

1.  Starts an HTTP server on port 80 to answer ACME challenges.
2.  Generates an account key and registers with Let's Encrypt.
3.  Orders a certificate for your domain.
4.  Solves the HTTP-01 challenge automatically.
5.  Downloads the certificate and private key.
6.  Starts an HTTPS server on port 443 using the new certificate.
