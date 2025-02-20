#!/bin/bash
# Nginx Configuration Setup
# Created by: Defebs-vpn
# Date: 2025-02-20 15:34:12
# Version: 4.0

setup_nginx() {
    echo -e "${YELLOW}Setting up Nginx with Multi-Protocol Support...${NC}"
    
    # Create webroot directory
    mkdir -p /var/www/html
    
    # Create default index page
    cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>${DOMAIN}</title>
    <meta name="robots" content="noindex, nofollow">
</head>
<body>
    <h1>Welcome to ${DOMAIN}</h1>
</body>
</html>
EOF

    # Create Nginx main configuration
    cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_buffer_size 4k;
    
    # Logging Settings
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    
    # Buffer Settings
    client_max_body_size 10m;
    client_body_buffer_size 128k;
    proxy_buffer_size 64k;
    proxy_buffers 8 64k;
    proxy_busy_buffers_size 128k;
    
    # Timeouts
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
EOF

    # Create Nginx server configuration
    cat > /etc/nginx/conf.d/${DOMAIN}.conf <<EOF
# HTTP Server (Redirect to HTTPS)
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
    
    # Allow WebSocket without TLS
    location /vmess-nontls {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${PORTS[XRAY_VMESS_NONTLS]};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Non-TLS SSH WebSocket
    location /ssh-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${PORTS[SSH_WS]};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    
    # SSL Configuration
    ssl_certificate ${SSL_DIR}/${DOMAIN}/fullchain.crt;
    ssl_certificate_key ${SSL_DIR}/${DOMAIN}/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # Root Directory
    root /var/www/html;
    index index.html index.htm;
    
    # Default Location
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # SSH WebSocket
    location /ssh-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${PORTS[SSH_WSS]};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # VMess WebSocket
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${PORTS[XRAY_VMESS_TLS]};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # VLESS WebSocket
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${PORTS[XRAY_VLESS_TLS]};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Trojan WebSocket
    location /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${PORTS[XRAY_TROJAN_TLS]};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # gRPC Configuration
    location ^~ /vless-grpc {
        grpc_pass grpc://127.0.0.1:${PORTS[XRAY_VLESS_GRPC]};
        grpc_connect_timeout 60s;
        grpc_read_timeout 60s;
        grpc_send_timeout 60s;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location ^~ /vmess-grpc {
        grpc_pass grpc://127.0.0.1:${PORTS[XRAY_VMESS_GRPC]};
        grpc_connect_timeout 60s;
        grpc_read_timeout 60s;
        grpc_send_timeout 60s;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location ^~ /trojan-grpc {
        grpc_pass grpc://127.0.0.1:${PORTS[XRAY_TROJAN_GRPC]};
        grpc_connect_timeout 60s;
        grpc_read_timeout 60s;
        grpc_send_timeout 60s;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Control Panel (Optional)
    location /panel {
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        try_files \$uri \$uri/ /panel/index.php?\$args;
    }
    
    # Status Page (Protected)
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
    
    # PHP Configuration
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

    # Create basic authentication for panel
    if [ ! -f /etc/nginx/.htpasswd ]; then
        echo -n "admin:" > /etc/nginx/.htpasswd
        openssl passwd -apr1 "your_password" >> /etc/nginx/.htpasswd
    fi

    # Set proper permissions
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html

    # Test and reload Nginx
    nginx -t && systemctl reload nginx

    echo -e "${GREEN}Nginx configuration completed successfully!${NC}"
}