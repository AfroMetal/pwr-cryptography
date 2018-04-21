package actors

import (
	"crypto/cipher"
	"crypto/aes"
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"crypto/rand"
)

type Alice struct {
	Puzzles [][]byte
	key []byte
}

func (a *Alice) SolvePuzzle(n uint, b *Bob) (err error) {
	var N uint64
	var message, puzzle, id, puzzleKey, randomKey, key []byte
	var block cipher.Block
	var blockMode cipher.BlockMode
	
	N = 1 << n
	
	var randIndex *big.Int
	randIndex, err = rand.Int(rand.Reader, big.NewInt(int64(N)))
	if err != nil { return err }
	puzzle = a.Puzzles[randIndex.Int64()]
	
	
	var i uint64
	for i = 0; true; i++ {
		key = make([]byte, 16)
		randomKey = make([]byte, n/8)
		
		_, err = rand.Read(randomKey)
		if err != nil {
			return err
		}
		key = append(key[:16-n/8], randomKey...)
		
		message = make([]byte, 48)
		
		block, err = aes.NewCipher(key)
		if err != nil { return err}
		blockMode = cipher.NewCBCDecrypter(block, key)
		blockMode.CryptBlocks(message, puzzle)
		
		if bytes.Equal(message[32:], make([]byte, 16)) {
			id = message[:16]
			puzzleKey = message[16:32]
			a.key = puzzleKey
			ok := b.SelectKey(id)
			if !ok {
				return errors.New("id not in map")
			}
			ok = b.VerifyKey(a.key)
			if !ok {
				return errors.New("keys do not match")
			} else {
				fmt.Printf("checked %d keys\n", i)
				return nil
			}
		}
	}
	
	return errors.New("key not found")
}
