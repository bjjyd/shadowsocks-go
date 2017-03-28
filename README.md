# shadowsocks-go

[![Build Status](https://travis-ci.org/ijyd/shadowsocks-go.svg?branch=master)](https://travis-ci.org/ijyd/shadowsocks-go/)

shadowsocks-go is a lightweight tunnel proxy which can help you get through firewalls. It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

The protocol is compatible with the origin shadowsocks (if both have been upgraded to the latest version).

# Install & Simple Run

You can also install from source (assume you have go installed):

```
git clone  https://github.com/bjjyd/shadowsocks-go
cd shadowsocks-go/cmd/shadowss/server/
go build -a  -o shadowss
./shadowss --alsologtostderr=true --config-file="/etc/server-multi-port.json" &
```

It's recommended to disable cgo when compiling shadowsocks-go. This will prevent the go runtime from creating too many threads for dns lookup.



# Usage

the server  program will look for `config.json` . You can use `--config-file` option to specify  configuration file.

Configuration file is in json format like this:

```
{
	"clients": [
		{
			"host":"0.0.0.0",
			"port":18387,
			"encrypt":"aes-128-cfb",
			"password":"barfoo",
			"enableOTA":false,
			"timeout":60
		},
		{
			"host":"0.0.0.0",
			"port":18388,
			"encrypt":"aes-128-cfb",
			"password":"foobar",
			"enableOTA":false,
			"timeout":60
		}
	]
}
```

## About encryption methods

AES is recommended for shadowsocks-go. [Intel AES Instruction Set](http://en.wikipedia.org/wiki/AES_instruction_set) will be used if available and can make encryption/decryption very fast. To be more specific, **`aes-128-cfb` is recommended as it is faster and [secure enough](https://www.schneier.com/blog/archives/2009/07/another_new_aes.html)**.

**rc4 and table encryption methods are deprecated because they are not secure.**

## Command line options

Command line options support debug and other feature. Use `-h` option to see all available options.

```
Usage of ./shadowss:
      --alsologtostderr value    log to standard error as well as files
      --config-file string       specify a configure file for server run.
      --cpu-core-num int         specify how many cpu core will be alloc for program (default 1)
      --enable-udp-relay         enable udp relay
      --log-backtrace-at value   when logging hits line file:N, emit a stack trace (default :0)
      --log-dir value            If non-empty, write log files in this directory
      --logtostderr value        log to standard error instead of files
      --stderrthreshold value    logs at or above this threshold go to stderr (default 2)
  -v, --v value                  log level for V logs
      --vmodule value            comma-separated list of pattern=N settings for file-filtered logging
```

**if specify --enable-udp-relay=true will be enable udp relay with server. we use  ss-tunnel as client (see shadowsocks-libev). **


# Extended Feature

- automatically opens firewall port,  the currently configure port
- multi user  base on configure file
