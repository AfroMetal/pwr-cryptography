package factorization

import (
	"os"
	"crypto/x509"
	"encoding/pem"
	"crypto/rsa"
	"os/exec"
	"math/big"
	"bytes"
	"../utils"
)

const sieveFile  = "/home/radoslaw/pwr/mgr/cryptography/lab/task5/files/sieve.sh"

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

func ReadKey(f *os.File) (pub *rsa.PublicKey) {
	fi, err := f.Stat()
	utils.Check(err)
	publicBytes := make([]byte, fi.Size())
	f.Read(publicBytes)

	block, _ := pem.Decode(publicBytes)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	utils.Check(err)
	
	pub = cert.PublicKey.(*rsa.PublicKey)
	return
}

func Factorize(pub *rsa.PublicKey) (p, q *big.Int) {
	cmd := exec.Command(sieveFile, pub.N.String())
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	
	line, err := out.ReadString('\n')
	utils.Check(err)
	p.SetString(line, 10)
	
	line, err = out.ReadString('\n')
	utils.Check(err)
	q.SetString(line, 10)
	
	return
}

func CalculatePrivateKey(n, p, q *big.Int, e int) (priv *rsa.PrivateKey) {
	nn := new(big.Int).Mul(p, q)
	
	if nn.Cmp(n) != 0 {
		panic("p*q != n")
	}
	
	p1 := new(big.Int).Sub(p, bigOne)
	q1 := new(big.Int).Sub(q, bigOne)
	totient := new(big.Int)
	totient.Mul(p1, q1)
	
	d := new(big.Int)
	d.ModInverse(big.NewInt(int64(e)), totient)
	
	priv = new(rsa.PrivateKey)
	
	priv.E = e
	priv.Primes = []*big.Int{p, q}
	priv.D = d
	priv.N = n

	priv.Precompute()
	
	err := priv.Validate()
	utils.Check(err)
	
	return priv
}

func WriteKey(f *os.File, priv *rsa.PrivateKey) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	utils.Check(err)
	var pemkey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	err = pem.Encode(f, pemkey)
	utils.Check(err)
	return
}
