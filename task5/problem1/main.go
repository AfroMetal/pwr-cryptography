package main

import (
	"os"
	"fmt"
	"./factorization"
	"./utils"
	"flag"
	"crypto/rsa"
	"math/big"
	"bufio"
)

const CertFile  = "/home/radoslaw/pwr/mgr/cryptography/lab/task5/files/cacertificate.pem"
const FactorsFile  = "/home/radoslaw/pwr/mgr/cryptography/lab/task5/files/factors.txt"
const OutFile  = "/home/radoslaw/pwr/mgr/cryptography/lab/task5/files/priv.key"


func main() {
	var certFile string
	flag.StringVar(&certFile,
		"i", CertFile,
		"certificate to factor path")
	var factorsFile string
	flag.StringVar(&factorsFile,
		"f", FactorsFile,
		"factors path")
	var outFile string
	flag.StringVar(&outFile,
		"o", OutFile,
		"output private key path")
	var factorOnly bool
	flag.BoolVar(&factorOnly,
		"factor-only", false,
			"only factor the N value")
	var genOnly bool
	flag.BoolVar(&genOnly,
		"gen-only", false,
			"only generate the private key, uses factors file (-f) as input")
	
	flag.Parse()
	
	if factorOnly && genOnly {
		panic("only one of factor-only and gen-only flags can be used")
	}
	
	var pub *rsa.PublicKey
	var priv *rsa.PrivateKey
	p := new(big.Int)
	q := new(big.Int)
	var f *os.File
	var err error
	
	f, err = os.Open(certFile)
	utils.Check(err)
	
	pub = factorization.ReadKey(f)
	f.Close()
	
	fmt.Printf("RSA public key:\nN=%d\nE=%d\n", pub.N, pub.E)
	
	
	if !genOnly {
		fmt.Println("Factorization...")
		p, q = factorization.Factorize(pub)
		f, err = os.OpenFile(factorsFile, os.O_APPEND|os.O_WRONLY, 0644)
		utils.Check(err)
		f.WriteString(fmt.Sprintf("%s\n%s", p.String(), q.String()))
		f.Close()
	} else {
		fmt.Println("Reading factors from file:")
		f, err = os.Open(factorsFile)
		utils.Check(err)
		scanner := bufio.NewScanner(f)
		ok := scanner.Scan()
		if ok {
			p.SetString(scanner.Text(), 10)
		} else {
			panic("can't read first factor")
		}
		ok = scanner.Scan()
		if ok {
			q.SetString(scanner.Text(), 10)
		} else {
			panic("can't read second factor")
		}
		f.Close()
	}
	
	fmt.Printf("p=%d\nq=%d\n", p, q)
	
	if factorOnly {
		fmt.Printf("Factors saved in %s\n", factorsFile)
		return
	}
	
	priv = factorization.CalculatePrivateKey(pub.N, p, q, pub.E)
	
	fmt.Printf("RSA private key:\nN=%d\nD=%d\n", priv.N, priv.D)
	
	f, err = os.Create(outFile)
	utils.Check(err)
	factorization.WriteKey(f, priv)
	f.Close()
	fmt.Printf("Private key saved in %s\n", outFile)
}
