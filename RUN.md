Configuration:

* Run kind: Package
```shell
docker run -d \
    --security-opt no-new-privileges \
    -p 127.0.0.1:18080:18080 \
    --restart unless-stopped \
    --name apkcombo-opera-proxy \
    apkcombo-opera-proxy
```