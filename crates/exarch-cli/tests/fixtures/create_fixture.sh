#!/bin/bash
cd "$(dirname "$0")"
echo "This is a sample file for testing." > sample.txt
tar czf sample.tar.gz sample.txt
rm sample.txt
echo "Created sample.tar.gz"
