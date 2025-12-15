#!/bin/bash
# Copyright 2025 wangxhzc
# SPDX-License-Identifier: Apache-2.0

if [ ! -f server.key ]; then
  openssl genrsa -out server.key 2048
fi

if [ ! -f server.pem ]; then
  openssl req -new -x509 -key server.key -out server.pem -days 365 -subj "/C=CN/ST=SHANGHAI/L=SHANGHAI/O=wangxhzc/OU=wangxhzc/CN=server.wangxhzc"
fi

export AGENT_LOG_LEVEL=ERROR
python3 agent.py --port 18443 --cert server.pem --key server.key
