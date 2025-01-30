#!/bin/bash

# Check library installations and versions
check_libraries() {
    echo "Library Verification Report"
    echo "=========================="

    # OpenSSL
    echo -n "OpenSSL: "
    openssl version

    # libcurl
    echo -n "libcurl: "
    curl --version | head -n 1

    # Compiler
    echo -n "GCC: "
    gcc --version | head -n 1
}

# Run verification
check_libraries
