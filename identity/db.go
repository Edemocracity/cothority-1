package identity

import (
	"sync"

	"github.com/dedis/cothority"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
	"github.com/dedis/protobuf"
)

// DB-versioning, allows propoer passage from one version to another. This example
// shows how to handle the case where there was no previous versioning in the
// database, and we already have two possible incompatible versions out there,
// version 0a and 0b. Version 1 will be the correct one.
//
// loadVersion starts trying to get version 1, but only if the database returns
// the correct version. If the version is 0 (or nonexistant), then it calls first
// load0a, if that fails it tries load0b and if all fails it returns an error.
//
// In case of a future incompatible change, one would have to add `load2` which
// would call `load1` if the version < 1, and `load1` would have to be changed
// to return `storage1` instead of `Storage`. And then the old `Storage` struct
// could be copied as `storage1`.

const dbVersion = 1

var storageKey = []byte("storage")
var versionKey = []byte("version")

func loadVersion(l onet.ContextDB) (*Storage, error) {
	vers, err := l.LoadVersion()
	if err != nil {
		return nil, err
	}
	if vers < dbVersion {
		return load0(l, vers)
	}
	sInt, err := l.Load(storageKey)
	if err != nil {
		return nil, err
	}
	return sInt.(*Storage), err
}

// load0 tries first to load the oldest version of the database, then the
// somewhat newer one.
func load0(l onet.ContextDB, vers int) (*Storage, error) {
	s := &Storage{}
	err := load0a(l, s)
	if err == nil {
		return s, nil
	}
	return s, load0b(l, s)
}

//
// This is the oldest version of the database.
//

type storage0a struct {
	Identities map[string]*idBlock0
	// OldSkipchainKey is a placeholder for protobuf being able to read old config-files
	OldSkipchainKey kyber.Scalar
	// The key that is stored in the skipchain service to authenticate
	// new blocks.
	SkipchainKeyPair *key.Pair
	// Auth is a list of all authentications allowed for this service
	Auth *authData
}

type idBlock0 struct {
	sync.Mutex
	Latest          *Data
	Proposed        *Data
	LatestSkipblock *skipchain.SkipBlock
}

func load0a(l onet.ContextDB, s *Storage) error {
	s0Buf, err := l.LoadRaw(storageKey)
	if err != nil {
		return err
	}
	if len(s0Buf) <= 16 {
		return nil
	}
	s0 := &storage0a{}
	err = protobuf.DecodeWithConstructors(s0Buf[16:], s0, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return err
	}
	s.Identities = make(map[string]*IDBlock)
	for k, v := range s0.Identities {
		s.Identities[k] = &IDBlock{
			Latest:          v.Latest,
			Proposed:        v.Proposed,
			LatestSkipblock: v.LatestSkipblock,
		}
	}
	s.SkipchainKeyPair = s0.SkipchainKeyPair
	return nil
}

//
// This is a somewhat newer version of the database.
//

type storage0b struct {
	Identities map[string]*IDBlock
	// OldSkipchainKey is a placeholder for protobuf being able to read old config-files
	OldSkipchainKey kyber.Scalar
	// The key that is stored in the skipchain service to authenticate
	// new blocks.
	SkipchainKeyPair *key.Pair
	// Auth is a list of all authentications allowed for this service
	Auth *authData
}

func load0b(l onet.ContextDB, s *Storage) error {
	s0Buf, err := l.LoadRaw(storageKey)
	if err != nil {
		return err
	}
	if len(s0Buf) <= 16 {
		return nil
	}
	s0 := &storage0b{}
	err = protobuf.DecodeWithConstructors(s0Buf[16:], s0, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return err
	}
	s.Identities = s0.Identities
	s.SkipchainKeyPair = s0.SkipchainKeyPair
	s.Auth = s0.Auth
	return nil
}
