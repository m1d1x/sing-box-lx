package main

// hikkari: hot reload control channel.
//
// With --hikkari-control the core reads commands from stdin, one per line.
// stdin belongs to the process that started the core (the Hikkari service),
// so nothing else on the machine can send them, unlike the loopback Clash API.
//
//	hikkari:reload <sha256 of the config file, hex>
//
// re-reads the -c file, checks it is the one the service wrote, and applies it
// in place when only outbounds and group members changed. The answer is one
// line on stdout:
//
//	hikkari:reload-result {"hash":…,"applied":true,…}
//	hikkari:reload-result {"hash":…,"applied":false,"declined":"<what needs a restart>"}
//	hikkari:reload-result {"hash":…,"applied":false,"error":"…"}
//
// Declined or failed, the running box is exactly as before and the service
// restarts the core the usual way.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	hikkariReloadCommand = "hikkari:reload "
	hikkariReloadResult  = "hikkari:reload-result "
	// hikkariMaxCommand bounds one stdin line.
	hikkariMaxCommand = 4096
)

var hikkariControl bool

func init() {
	commandRun.Flags().BoolVar(&hikkariControl, "hikkari-control", false, "read hot reload commands from stdin (Hikkari service)")
}

type hikkariReloadRequest struct {
	hash string
}

type hikkariReloadReply struct {
	Hash string `json:"hash"`
	box.HotReloadResult
	Error string `json:"error,omitempty"`
}

// hikkariControlRequests starts the stdin reader. A nil channel (flag off)
// blocks forever in a select, which is what the run loop wants.
func hikkariControlRequests() <-chan hikkariReloadRequest {
	if !hikkariControl {
		return nil
	}
	requests := make(chan hikkariReloadRequest)
	go func() {
		reader := bufio.NewReaderSize(os.Stdin, hikkariMaxCommand)
		for {
			line, err := readHikkariLine(reader)
			if err != nil {
				if err != io.EOF {
					log.Error(E.Cause(err, "hikkari control"))
				}
				return
			}
			if line == "" {
				continue
			}
			hash, isReload := strings.CutPrefix(line, hikkariReloadCommand)
			if !isReload {
				log.Warn("hikkari control: unknown command")
				continue
			}
			requests <- hikkariReloadRequest{hash: strings.ToLower(strings.TrimSpace(hash))}
		}
	}()
	return requests
}

func readHikkariLine(reader *bufio.Reader) (string, error) {
	line, isPrefix, err := reader.ReadLine()
	if err != nil {
		return "", err
	}
	if isPrefix {
		for isPrefix && err == nil {
			_, isPrefix, err = reader.ReadLine()
		}
		return "", E.New("command longer than ", hikkariMaxCommand, " bytes")
	}
	return strings.TrimSpace(string(line)), nil
}

// hikkariReload handles one request against the running instance. On success
// current is the entry the instance now runs.
func hikkariReload(instance *box.Box, current *OptionsEntry, request hikkariReloadRequest) (*OptionsEntry, hikkariReloadReply) {
	reply := hikkariReloadReply{Hash: request.hash}
	if current == nil {
		reply.Declined = "hot reload needs a single -c config file"
		return nil, reply
	}
	next, err := readConfigAt(current.path)
	if err != nil {
		reply.Error = err.Error()
		return nil, reply
	}
	sum := sha256.Sum256(next.content)
	if hex.EncodeToString(sum[:]) != request.hash {
		reply.Error = "config file does not match the requested hash"
		return nil, reply
	}
	result, err := instance.HotReload(current.content, next.content, next.options)
	reply.HotReloadResult = result
	if err != nil {
		reply.Error = err.Error()
		return nil, reply
	}
	if !result.Applied {
		return nil, reply
	}
	return next, reply
}

var hikkariReplyAccess sync.Mutex

func writeHikkariReply(reply hikkariReloadReply) {
	content, err := json.Marshal(reply)
	if err != nil {
		log.Error(E.Cause(err, "hikkari control: encode reply"))
		return
	}
	hikkariReplyAccess.Lock()
	defer hikkariReplyAccess.Unlock()
	// One write per line: the log shares stdout and writes whole lines too.
	_, _ = os.Stdout.Write(append(append([]byte(hikkariReloadResult), content...), '\n'))
}

// hikkariSingleEntry is the entry hot reload compares against: only a run
// from exactly one config file can be reloaded from it.
func hikkariSingleEntry(optionsList []*OptionsEntry) *OptionsEntry {
	if len(optionsList) != 1 || len(configDirectories) > 0 || optionsList[0].path == "stdin" {
		return nil
	}
	return optionsList[0]
}
