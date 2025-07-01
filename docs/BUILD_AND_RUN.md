# Navigate to the liboqs folder
cd ~/IIoT_MMT/liboqs

# Create and enter a build directory
mkdir -p build && cd build

# Configure and install
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install

# Navigate to the OpenSSL-1.1 folder
cd ~/IIoT_MMT/openssl-1.1

# Configure and build
./config --prefix=/usr/local/openssl-1.1 shared enable-dso
make -j$(nproc)
sudo make install

# Add OpenSSL-1.1 to your PATH
export PATH=/usr/local/openssl-1.1/bin:$PATH

# Navigate to project root
cd ~/IIoT_MMT

# Create and enter build directory
mkdir -p build && cd build

# Configure project
cmake ..

# Compile using all CPU cores
make -j$(nproc)

# Binaries produced:
#   - kem_test  at ../scripts/kem_test
#   - main_app  at ../scripts/main_app

# Change to scripts directory
cd ~/IIoT_MMT/scripts

# Run benchmark
./kem_test
# Sample output:
# KeyGen: 1.234 ms
# Encaps: 0.678 ms
# Decaps: 0.456 ms
# Shared OK: yes

# In the same scripts directory
./main_app
# Sample output:
# [*] Generating PQC KEM keypair...
# [*] Encapsulating...
# [*] Decapsulating...
# Shared secret match!
