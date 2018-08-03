# Nginx
##Nginx Configuration With Node.js
```  
 
server {
    listen 80;

    # Listen to your server ip address
    server_name {{ip_address}};

    # Redirect all traffic comming from your-server-ip to your domain
    return 301 $scheme://{{url_address}}$request_uri;
}
server {
    listen 80 ; # default_server;
    listen [::]:80; # default_server;
    server_name {{www.domain.com}} {{domain.com}};

    # Redirect all HTTP requests to HTTPS with a 301 Moved Permanently response.
    return 301 https://$host$request_uri;
}

server {
       listen 443 ssl http2;
		listen [::]:443 ssl http2;
		server_name {{www.domain.com}} {{domain.com}};
		#root /var/www/vhosts/domain.com/httpdocs/web/dist/assets/;

		ssl on;
      	ssl_certificate /etc/letsencrypt/live/domain.com/fullchain.pem;
    	ssl_certificate_key /etc/letsencrypt/live/domain.com/privkey.pem;
		ssl_session_timeout 1d;
		ssl_session_cache shared:SSL:50m;
		ssl_session_tickets off;


     	access_log /var/log/nginx/nginx.vhost.access.log;
  		error_log /var/log/nginx/nginx.vhost.error.log;


		# intermediate configuration. tweak to your needs.
   		 ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
   		 ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS';
   		 ssl_prefer_server_ciphers on;

   		 # HSTS (ngx_http_headers_module is required) (15768000 seconds = 6 months)
   		 add_header Strict-Transport-Security max-age=15768000;

   		 # OCSP Stapling ---
    		# fetch OCSP records from URL in ssl_certificate and cache them
    		ssl_stapling on;
    		ssl_stapling_verify on;
		resolver 8.8.8.8;


		proxy_set_header Host $http_host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;


		location /socket.io/ {
			proxy_set_header X-Real-IP $remote_addr;
      			proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      			proxy_set_header Host $http_host;
      			proxy_set_header X-NginX-Proxy true;

      			proxy_pass https://localhost:8483/socket.io/;
      			proxy_redirect off;

     			proxy_http_version 1.1;
     			proxy_set_header Upgrade $http_upgrade;
      			proxy_set_header Connection "upgrade";

		}

		location /app/ {
			proxy_http_version 1.1;

			proxy_set_header Upgrade $http_upgrade;
			proxy_set_header Connection "upgrade";

                	proxy_pass "https://localhost:8483/";
		}

		location /api/v1/dev/ {
                        proxy_http_version 1.1;

                        proxy_set_header Upgrade $http_upgrade;
                        proxy_set_header Connection "upgrade";

                        proxy_pass "https://localhost:8283/";
                }
		location /sdev/ {
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header Host $http_host;
                        proxy_set_header X-NginX-Proxy true;

                        proxy_pass https://localhost:8283/socket.io/;
                        proxy_redirect off;

                        proxy_http_version 1.1;
                        proxy_set_header Upgrade $http_upgrade;
                        proxy_set_header Connection "upgrade";

		      	# proxy_pass https://127.0.0.1:8283/socket.io/;
    		 	# proxy_http_version 1.1;
    			proxy_set_header Upgrade $http_upgrade;
    			proxy_set_header Connection "upgrade";
    			proxy_set_header Host $host;
    			proxy_cache_bypass $http_upgrade;

                }


		location /interne/ {
			proxy_http_version 1.1;

         	proxy_set_header Upgrade $http_upgrade;
         	proxy_set_header Connection "upgrade";

			proxy_pass "https://localhost:8686/";
		}

		location /web/ {
			proxy_http_version 1.1;

          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection "upgrade";
			proxy_pass "https://localhost:8987/";
			#root /var/www/vhosts/domain.com/httpdocs/Web/;
			#index index.html;
		}

		location /pro/domain/ {
			proxy_http_version 1.1;

          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection "upgrade";
          proxy_pass "https://localhost:8558/";

			#root /var/www/vhosts/domain.com/httpdocs/domain_pro/domainPro/dist/;
          #index index.html;

		}

		location / {
			#proxy_pass "https://localhost:8082/";
			root /var/www/vhosts/domain.com/httpdocs/;
			index index.html;
		}

		location /cgv/ {
			root /var/www/vhosts/domain.com/httpdocs/CGV/;
			index index.html;
		}
		location /cgu/ {
          root /var/www/vhosts/domain.com/httpdocs/CGU/;
          index index.html;
                }

		error_page 404 500 501 503 504 /index.html;
		    location =  {
			#root /var/www/vhosts/domain.com/httpdocs/;
			#index index.html;
			return 301 $scheme://domain.com$request_uri;
		}

        }
```

