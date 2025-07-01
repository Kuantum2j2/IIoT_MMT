# On MMT-PC (server):
openssl s_server \
  -accept 8443 \
  -cert ~/IIoT_MMT/certs/server_mmt.crt \
  -key  ~/IIoT_MMT/certs/server_mmt.key \
  -ciphersuites TLS_AES_256_GCM_SHA384_KYBER_768 \
  -provider base -provider oqsprovider -www

# On SOC-PC (client):
openssl s_client \
  -connect <MMT-PC-IP>:8443 \
  -ciphersuites TLS_AES_256_GCM_SHA384_KYBER_768 \
  -provider oqsprovider
