#!/bin/bash

# Define directories
CERT_DIR="./certificates" 
PRIVATE_KEY_DIR="${CERT_DIR}/privateKey"
SCRIPT_DIR="$(dirname "$0")"
CSR_CONFIG="${SCRIPT_DIR}/conf/csr.conf"

# Create directories
mkdir -p ${CERT_DIR}
mkdir -p ${PRIVATE_KEY_DIR}

# Function to generate certificates for a specific security policy
generate_cert() {
    local POLICY=$1
    local KEY_SIZE=$2
    local HASH_ALG=$3
    
    echo "Generating certificates for ${POLICY}..."
    
    # Export policy name for CSR config
    export POLICY_NAME="${POLICY}"
    
    # Generate private key
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${KEY_SIZE} \
        -out "${PRIVATE_KEY_DIR}/${POLICY}.key"
    
    # Generate CSR
    openssl req -new \
        -key "${PRIVATE_KEY_DIR}/${POLICY}.key" \
        -out "${CERT_DIR}/${POLICY}.csr" \
        -config "${CSR_CONFIG}"
    
    # Generate self-signed certificate
    openssl x509 -req -days 365 \
        -in "${CERT_DIR}/${POLICY}.csr" \
        -signkey "${PRIVATE_KEY_DIR}/${POLICY}.key" \
        -${HASH_ALG} \
        -extensions v3_req \
        -extfile "${CSR_CONFIG}" \
        -out "${CERT_DIR}/${POLICY}.crt"
    
    # Convert to DER format
    openssl x509 -in "${CERT_DIR}/${POLICY}.crt" \
        -outform der -out "${CERT_DIR}/${POLICY}.der"
    
    # Clean up CSR
    rm "${CERT_DIR}/${POLICY}.csr"
    
    # Set permissions
    chmod 600 "${PRIVATE_KEY_DIR}/${POLICY}.key"
    chmod 644 "${CERT_DIR}/${POLICY}.crt" "${CERT_DIR}/${POLICY}.der"
}

# Generate certificates for each security policy
generate_cert "Basic128Rsa15" "2048" "sha1"
generate_cert "Basic256" "2048" "sha1"
generate_cert "Basic256Sha256" "2048" "sha256"
generate_cert "Aes128_Sha256_RsaOaep" "2048" "sha256"
generate_cert "Aes256_Sha256_RsaPss" "3072" "sha256"

echo "All certificates generated successfully!"