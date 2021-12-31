module github.com/jchavannes/btcd

replace github.com/jchavannes/btcutil => ../btcutil

go 1.16

require (
	github.com/btcsuite/btcrpcclient v0.0.0-20170619204338-45b9cb481d2a
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/btcsuite/goleveldb v1.0.0
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/btcsuite/winsvc v1.0.0
	github.com/davecgh/go-spew v1.1.1
	github.com/jchavannes/btclog v0.0.0-20211231060513-6ff05f5c3d70
	github.com/jchavannes/btcutil v0.0.0-20211231100032-d7a7a6b780ee
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
)
