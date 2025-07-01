# 1. Navigate to the project root
cd ~/IIoT_MMT

# 2. Create and enter the build directory
mkdir -p build && cd build

# 3. Configure the project with CMake
cmake ..

# 4. Compile using all available CPU cores
make -j$(nproc)

# 5. After a successful build, the binaries will be located at:
#    - kem_test   in ../scripts/kem_test
#    - main_app   in ../scripts/main_app

cd ~/IIoT_MMT/scripts
./kem_test
# Output:
# KeyGen: <time> ms
# Encaps: <time> ms
# Decaps: <time> ms
# Shared OK: yes

cd ~/IIoT_MMT/scripts
./main_app
# Output:
# [*] Generating PQC KEM keypair...
# [*] Encapsulating...
# [*] Decapsulating...
# Shared secret match!

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
