# shadowsocks libev client test

start shadows

```
shadowss --alsologtostderr=true --config-file="./server-multi-port.json" -v=6
```

start ss-local

https://github.com/EasyPi/docker-shadowsocks-libev/blob/master/docker-compose.yml

```
./ss-local -s 47.89.189.237 -p 18087 -k 44c096c8e1e5fd7a85ea0bbe4623778d -m aes-256-cfb -l 11080 -b 0.0.0.0
./ss-local -s 192.168.137.191 -p 18387 -k barfoo -m aes-128-cfb -l 11080 -b 0.0.0.0
```
