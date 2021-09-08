Copy `apkcombo-opera-proxy` binary to this path:

`/usr/local/bin/apkcombo-opera-proxy`

> chmod +x /usr/local/bin/apkcombo-opera-proxy

Copy `apkcombo-opera-proxy.service` to `/etc/systemd/system/`

> systemctl enable apkcombo-opera-proxy
>
>service apkcombo-opera-proxy start
>
>service apkcombo-opera-proxy status

```bash
[Unit]
Description=APKCombo Opera Proxy Server

[Service]
ExecStart=/usr/local/bin/apkcombo-opera-proxy
Restart=always

[Install]
WantedBy=multi-user.target 
```

