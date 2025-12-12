# Steps
 - Create a k3s cluster
 - Install vcluster if you're planning to test it
 ```bash
 curl -L -o vcluster "https://github.com/loft-sh/vcluster/releases/download/v0.30.2/vcluster-linux-amd64" && sudo install -c -m 0755 vcluster /usr/local/bin && rm -f vcluster
 ```