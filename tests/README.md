## SSL Certificates

Create a private key and a certificate

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=PSTLab'
```

Convert the certificate to CRT format, which is required by the browser

```bash
openssl x509 -outform der -in cert.pem -out cert.crt
```