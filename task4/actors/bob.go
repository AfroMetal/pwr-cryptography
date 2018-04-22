package actors

import (
	"bytes"
	"errors"
	"math/big"
	"crypto/rand"
	"encoding/binary"
)

type Bob struct {
	key []byte
}

func (b *Bob) setKey(key []byte) {
	b.key = key
}

func (b *Bob) GetKey() []byte {
	return b.key
}

func (b *Bob) SolvePuzzle(n uint, channel chan []byte) (err error) {
	var N uint64
	
	N = 1 << n
	
	var randIndex *big.Int
	randIndex, err = rand.Int(rand.Reader, big.NewInt(int64(N)))
	if err != nil { return err }
	
	puzzle := make([]byte, 48)
	message := make([]byte, 48)
	
	var i uint64
	for i = 0; i < N; i++ {
		if i == randIndex.Uint64() {
			puzzle = <- channel
		} else {
			<- channel
		}
	}
	
	for i = 0; i < 1 << n; i++ {
		randomKey := make([]byte, 8)
		binary.BigEndian.PutUint64(randomKey, i)
		key := append(make([]byte, 8), randomKey...)
		
		Decrypt(key, puzzle, message, key)
		
		key = nil
		randomKey = nil
		
		if bytes.Equal(message[32:], make([]byte, 16)) {
			id := message[:16]
			channel <- id
			puzzleKey := message[16:32]
			b.setKey(puzzleKey)
			return nil
		}
		
	}
	
	return errors.New("key not found")
}
