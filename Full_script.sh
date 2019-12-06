#!/bin/sh
# vim: syntax=sh

# Generate Keys first
python3.6 user1KeyStoreGenerate.py
python3.6 user2KeyStoreGenerate.py

# Generate Certs
python3.6 user1Certificate.py
python3.6 user2Certificate.py

# Write message
python3.6 createUser1SecretKey.py

# Read Message
python3.6 verifyUser1Sig.py
