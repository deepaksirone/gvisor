package seclambda

import (
	"encoding/json"
	"fmt"
	zmq "github.com/deepaksirone/goczmq"
	"runtime"
	//"github.com/grpc/grpc-go"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/specutils"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func serveSandbox(sandBoxSide int) {

}

func ServeFDs(sandBoxSide int, seclambdaSide int) {
	log.Debugf("[Seclambda] Starting Seclambda Proxy with sandBoxSide: %v, seclambdaSide: %v", sandBoxSide, seclambdaSide)

}
