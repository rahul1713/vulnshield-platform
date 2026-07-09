# Cross-origin dashboard (e.g. :3002) → API gateway (:18080) sends OPTIONS before JWT requests.
if ($request_method = OPTIONS) {
    add_header Access-Control-Allow-Origin $cors_allow_origin always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, Content-Type, X-Request-ID" always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Access-Control-Max-Age 86400 always;
    return 204;
}
