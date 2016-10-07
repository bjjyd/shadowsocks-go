package options

import (
	"shadowsocks-go/pkg/config"

	"github.com/golang/glog"
	"github.com/spf13/pflag"
)

type ServerOption struct {
	ConfigFile     string
	CpuCoreNum     int
	EnableUDPRelay bool
}

func NewServerOption() *ServerOption {
	return &ServerOption{
		ConfigFile:     string(""),
		CpuCoreNum:     1,
		EnableUDPRelay: false,
	}
}

func (s *ServerOption) LoadConfigFile() error {
	glog.V(5).Infof("Parse %s file\r\n", s.ConfigFile)
	err := config.ServerCfg.Parse(s.ConfigFile)
	if err != nil {
		glog.Errorf("error reading %s: %v\n", s.ConfigFile, err)
		return err
	}

	return nil
}

func (s *ServerOption) AddFlags(fs *pflag.FlagSet) {

	fs.StringVar(&s.ConfigFile, "config-file", s.ConfigFile, ""+
		"specify a configure file for server run. ")

	fs.IntVar(&s.CpuCoreNum, "cpu-core-num", s.CpuCoreNum, ""+
		"specify how many cpu core will be alloc for program")

	fs.BoolVar(&s.EnableUDPRelay, "enable-udp-relay", s.EnableUDPRelay, ""+
		"enable udp relay")
}
