package main

import (
	"./actors"
	"fmt"
)

func main() {
	for _, n := range []uint{8, 16, 24, 32} {
		fmt.Printf("Puzzle for n=%d\n", n)
		var a= &actors.Alice{}
		var b= &actors.Bob{}
		err := b.PreparePuzzles(n)
		if err != nil {
			panic(err)
		} else {
			fmt.Printf("Prepared %d puzzles\n", len(b.Puzzles))
		}
		a.Puzzles = b.Puzzles
		err = a.SolvePuzzle(n, b)
		if err != nil {
			panic(err)
		} else {
			fmt.Println("Keys properly established")
		}
	}
}