FROM nginx:1.25-alpine
COPY nginx.conf cors-preflight.inc /etc/nginx/
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
