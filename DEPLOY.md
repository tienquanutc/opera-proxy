CGO_ENABLED=0 go build -v -a -tags netgo -ldflags '-s -w -extldflags "-static" -X main.version='"$GIT_DESC"
Copy `apkcombo-opera-proxy` binary to this path:

`/usr/local/bin/apkcombo-opera-proxy`

> chmod +x /usr/local/bin/apkcombo-opera-proxy

Copy `apkcombo-opera-proxy.service` to `/etc/systemd/system/`
> nano /etc/systemd/system/apkcombo-opera-proxy.service
> 
> systemctl enable apkcombo-opera-proxy
>
>service apkcombo-opera-proxy start
>
>service apkcombo-opera-proxy status

```bash
[Unit]
Description=APKCombo Opera Proxy Server

[Service]
ExecStart=/usr/local/bin/apkcombo-opera-proxy -countries EU,AM -numOfProxies 20 -sticky-ttl 10m -attempts 3 -verbosity 20
Restart=always

[Install]
WantedBy=multi-user.target 
```


## Logging

The service writes to the journal (`journalctl -u apkcombo-opera-proxy`). It is quiet: lifecycle, discovery results
and failures only - one line per request is `Debug`, which `-verbosity 20` does not print. Before 2026-10-07 the unit
had a drop-in at `/etc/systemd/system/apkcombo-opera-proxy.service.d/override.conf` setting
`StandardOutput=null` / `StandardError=null`, which threw away every line including the credentials the old build
printed; it was moved to `/root/apkcombo-opera-proxy-override.conf.bak`. If the output ever gets noisy again, lower
the verbosity rather than discarding it.

For a few seconds after a restart the proxy answers 503 (`no upstream endpoint available`) while the first discovery
runs - it comes up listening instead of exiting when SurfEasy is unreachable.
