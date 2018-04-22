package actors

import (
	"crypto/rand"
	"encoding/binary"
	"bytes"
	"errors"
	"log"
)

type Alice struct {
	puzzleKeysMap map[string][]byte
	key           []byte
}

func (a *Alice) VerifyKey(otherKey []byte) bool {
	return bytes.Equal(a.key, otherKey)
}

func (a *Alice) selectKey(id []byte) (ok bool) {
	a.key = make([]byte, 16)
	a.key, ok = a.puzzleKeysMap[string(id)]
	return ok
}

func (a *Alice) GetKey() []byte {
	return a.key
}

func (a *Alice) PreparePuzzles(n uint, channel chan []byte) (err error) {
	var N uint64
	var iv, k1, k2, puzzle []byte
	
	N = 1 << n
	a.puzzleKeysMap = make(map[string][]byte)
	iv = make([]byte, 16)
	k1 = make([]byte, 16)
	k2 = make([]byte, 16)

	_, err = rand.Read(k1)
	if err != nil {
		return err
	}
	_, err = rand.Read(k2)
	if err != nil {
		return err
	}
	
	puzzle = make([]byte, 48)
	id := make([]byte, 16)
	puzzleKey := make([]byte, 16)
	
	var i uint64
	for i = 0; i < N; i++ {
		RandomBytes(iv)
		iBytes := make([]byte, 16)
		binary.BigEndian.PutUint64(iBytes, i)
		Encrypt(k1, iBytes, id, iv)
		
		_, ok := a.puzzleKeysMap[string(id)]
		if ok {
			return errors.New("double id")
		}
		
		RandomBytes(iv)
		Encrypt(k2, id, puzzleKey, iv)
		
		randomKey := make([]byte, n/8)
		RandomBytes(randomKey)
		key := append(make([]byte, 16-n/8), randomKey...)
		
		message := append(id, append(puzzleKey, make([]byte, 16)...)...)
		Encrypt(key, message, puzzle, key)
		
		a.puzzleKeysMap[string(id)] = puzzleKey
		channel <- puzzle
		
		iBytes = nil
		randomKey = nil
		key = nil
		message = nil
	}
	
	log.Println("Puzzles prepared")
	
	keyId := <- channel
	a.selectKey(keyId)
	
	return nil
}
