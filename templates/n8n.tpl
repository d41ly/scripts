#=========================================================================#
# N8N Proxy Template. SSL is Forced.									  #
# https://hestiacp.com/docs/server-administration/web-templates.html      #
#=========================================================================#

server {
    listen      %ip%:%web_port%;
    server_name %domain_idn% %alias_idn%;

    include %home%/%user%/conf/web/%domain%/nginx.forcessl.conf*;
    include %home%/%user%/conf/web/%domain%/nginx.conf_*;
}
