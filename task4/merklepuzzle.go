package main

import (
	"./actors"
	"bytes"
	"time"
	"log"
)

func main() {
	for _, n := range []uint{16, 24, 32, 40} {
		log.Printf("Puzzle for n=%d\n", n)
		var a = &actors.Alice{}
		var b = &actors.Bob{}
		
		var communicationChannel = make(chan []byte)
		var aResult = make(chan error)
		var bResult = make(chan error)
		
		start := time.Now()
		
		go func(resultChannel chan error) {
			resultChannel <- a.PreparePuzzles(n, communicationChannel)
		}(aResult)
		go func(resultChannel chan error) {
			resultChannel <- b.SolvePuzzle(n, communicationChannel)
		}(bResult)
		
		if err := <-aResult; err != nil { panic(err) }
		if err := <-bResult; err != nil { panic(err) }
		
		elapsed := time.Since(start)
    	log.Printf("Puzzle took %s", elapsed)
		
		aKey := a.GetKey()
		bKey := b.GetKey()
		
		log.Printf("A key:\t%v\n", aKey)
		log.Printf("B key:\t%v\n", bKey)
		
		if bytes.Equal(aKey, bKey) {
			log.Println("Keys established correctly")
		} else {
			log.Println("Keys did not match")
		}
	}
}