#!/bin/bash

# Function to setup Xray with multiple protocols
setup_xray() {
    echo -e "${YELLOW}Setting up Xray Multi-Protocol Service...${NC}"
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Generate random UUIDs
    UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
    UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
    UUID_TROJAN=$(openssl rand -hex 16)
    
    # Create Xray config directory
    mkdir -p /usr/local/etc/xray
    
    # Create Xray config
    cat > /usr/local/etc/xray/config.json <<EOF
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning"
    },
    "api": {
        "tag": "api",
        "services": [
            "HandlerService",
            "LoggerService",
            "StatsService"
        ]
    },
    "stats": {},
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "statsUserUplink": true,
                "statsUserDownlink": true,
                "bufferSize": 64
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true,
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VMESS}",
                        "alterId": 0,
                        "email": "vmess@${DOMAIN}",
                        "security": "auto"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ],
                    "minVersion": "1.2",
                    "cipherSuites": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                },
                "wsSettings": {
                    "path": "/vmess",
                    "headers": {
                        "Host": "${DOMAIN}"
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 80,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VMESS}",
                        "alterId": 0,
                        "email": "vmess-nontls@${DOMAIN}"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess-nontls"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VLESS}",
                        "email": "vless@${DOMAIN}",
                        "encryption": "none"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VLESS}",
                        "email": "vless-grpc@${DOMAIN}"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                },
                "grpcSettings": {
                    "serviceName": "vless-grpc"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${UUID_TROJAN}",
                        "email": "trojan@${DOMAIN}"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${UUID_TROJAN}",
                        "email": "trojan-grpc@${DOMAIN}"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                },
                "grpcSettings": {
                    "serviceName": "trojan-grpc"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF

    # Create client config file
    cat > ${BASE_DIR}/config/xray-clients.txt <<EOF
X-ray Configuration Details
==========================
Domain: ${DOMAIN}
Last Update: $(date '+%Y-%m-%d %H:%M:%S')

VMess Configuration:
------------------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VMESS}
AlterID: 0
Security: auto
Network: ws
Path: /vmess
TLS: yes

VMess (Non-TLS):
--------------
Address: ${DOMAIN}
Port: 80
UUID: ${UUID_VMESS}
AlterID: 0
Security: auto
Network: ws
Path: /vmess-nontls
TLS: no

VLESS Configuration:
------------------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VLESS}
Network: ws
Path: /vless
TLS: yes

VLESS gRPC:
----------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VLESS}
Network: grpc
ServiceName: vless-grpc
TLS: yes

Trojan Configuration:
------------------
Address: ${DOMAIN}
Port: 443
Password: ${UUID_TROJAN}
Network: tcp
TLS: yes

Trojan gRPC:
----------
Address: ${DOMAIN}
Port: 443
Password: ${UUID_TROJAN}
Network: grpc
ServiceName: trojan-grpc
TLS: yes
EOF

    # Set proper permissions
    chmod 644 /usr/local/etc/xray/config.json
    chmod 644 ${BASE_DIR}/config/xray-clients.txt

    # Create log directory
    mkdir -p /var/log/xray
    chmod 755 /var/log/xray

    # Start Xray service
    systemctl enable xray
    systemctl restart xray

    echo -e "${GREEN}Xray has been installed and configured successfully!${NC}"
    echo -e "${YELLOW}Client configuration saved to: ${BASE_DIR}/config/xray-clients.txt${NC}"
}