package actors

import (
	"crypto/cipher"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"bytes"
	"errors"
)

type Bob struct {
	Puzzles       [][]byte
	puzzleKeysMap map[string][]byte
	key           []byte
}

func (b *Bob) VerifyKey(otherKey []byte) bool {
	return bytes.Equal(b.key, otherKey)
}

func (b *Bob) SelectKey(id []byte) (ok bool) {
	b.key = make([]byte, 16)
	b.key, ok = b.puzzleKeysMap[string(id)]
	return ok
}

func (b *Bob) FindKey(key []byte) (id string, ok bool) {
	for i, k := range b.puzzleKeysMap {
		if bytes.Equal(k, key) {
			return i, true
		}
	}
	return "", false
}

func (b *Bob) PreparePuzzles(n uint) (err error) {
	var N uint64
	var iv, k1, k2, iBytes, message, puzzle, id, puzzleKey, randomKey, key []byte
	var block cipher.Block
	var blockMode cipher.BlockMode
	
	N = 1 << n
	b.puzzleKeysMap = make(map[string][]byte)
	b.Puzzles = make([][]byte, N)
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
	
	var i uint64
	for i = 0; i < N; i++ {
		iBytes = make([]byte, 16)
		puzzleKey = make([]byte, 16)
		id = make([]byte, 16)
		randomKey = make([]byte, n/8)
		key = make([]byte, 16)
		message = make([]byte, 48)
	
		block, err = aes.NewCipher(k1)
		_, err = rand.Read(iv)
		if err != nil {
			return err
		}
		blockMode = cipher.NewCBCEncrypter(block, iv)
		binary.BigEndian.PutUint64(iBytes, i)
		blockMode.CryptBlocks(id, iBytes)
		
		_, ok := b.puzzleKeysMap[string(id)]
		if ok {
			return errors.New("double id")
		}
		
		block, err = aes.NewCipher(k2)
		_, err = rand.Read(iv)
		if err != nil {
			return err
		}
		blockMode = cipher.NewCBCEncrypter(block, iv)
		blockMode.CryptBlocks(puzzleKey, id)
		
		_, err = rand.Read(randomKey)
		if err != nil {
			return err
		}
		key = append(key[:16-n/8], randomKey...)
		
		message = append(message[:0], append(id, message[16:]...)...)
		message = append(message[:16], append(puzzleKey, message[32:]...)...)
		
		puzzle = make([]byte, 48)
		
		block, err = aes.NewCipher(key)
		blockMode = cipher.NewCBCEncrypter(block, key)
		blockMode.CryptBlocks(puzzle, message)
		
		b.puzzleKeysMap[string(id)] = puzzleKey
		b.Puzzles[i] = puzzle
	}
	
	return nil
}
