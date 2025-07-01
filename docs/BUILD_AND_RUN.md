# Build & Run IIoT_MMT

## 1. Build liboqs
```bash
cd ~/IIoT_MMT/liboqs
mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install

cd ~/IIoT_MMT/openssl-1.1
./config --prefix=/usr/local/openssl-1.1 shared enable-dso
make -j$(nproc)
sudo make install
export PATH=/usr/local/openssl-1.1/bin:$PATH

cd ~/IIoT_MMT/scripts
gcc -O2 kem_test.c -o kem_test \
    -I/usr/local/include -L/usr/local/lib -loqs
./kem_test

./main_app

openssl s_server \
  -accept 8443 \
  -cert ~/IIoT_MMT/certs/server_mmt.crt \
  -key  ~/IIoT_MMT/certs/server_mmt.key \
  -ciphersuites TLS_AES_256_GCM_SHA384_KYBER_768 \
  -provider base -provider oqsprovider -www

openssl s_client \
  -connect localhost:8443 \
  -ciphersuites TLS_AES_256_GCM_SHA384_KYBER_768 \
  -provider oqsprovider
