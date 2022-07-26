Configuration:

## Install gvm

* go 1.16 only

```
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang-go
bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)
source /root/.gvm/scripts/gvm
apt-get install bison
gvm install go1.16
gvm use go1.16
go version
```

* Run kind: Package

```shell
docker run -d \
    --security-opt no-new-privileges \
    -p 0.0.0.0:18080:18080 \
    --restart unless-stopped \
    --name apkcombo-opera-proxy \
    tienquandev/opera-proxy
```