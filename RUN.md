Configuration:

* Run kind: Package
```shell
docker run -d \
    --security-opt no-new-privileges \
    -p 0.0.0.0:18080:18080 \
    --restart unless-stopped \
    --name apkcombo-opera-proxy \
    tienquandev/opera-proxy
```