#!/bin/bash

# Base GRPC function to test
grpcurl -plaintext -import-path ../lib_lime/proto -proto lime.proto -d '{"name":"asdf"}' '[::]:50051' lime.Lime/Send

# Get the list of broadcast SSIDs
echo "Getting list of broadcast SSIDs"
grpcurl -plaintext -import-path ../lib_lime/proto -proto lime.proto -d '' '[::]:50051' lime.Lime/GetBroadcast

# Get the list of SSIDs discovered via probes
echo "Get the list of SSIDs discovered via probes"
grpcurl -plaintext -import-path ../lib_lime/proto -proto lime.proto -d '' '[::]:50051' lime.Lime/GetProbes


# Get the list of handshakes
echo "Getting handshakes..."
grpcurl -plaintext -import-path ../lib_lime/proto -proto lime.proto -d '' '[::]:50051' lime.Lime/GetHandshakes