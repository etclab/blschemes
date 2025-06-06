package bgoy

import (
	"fmt"
	"log"
)

func Example() {
	m := []byte("the lazy dog jumped over the quick brown fox")

	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	pubkeys := []*PublicKey{alicePK, bobPK}

	muSig := NewSignature()

	err := Sign(pp, aliceSK, m, muSig, nil)
	if err != nil {
		log.Fatalf("Alice sign failed: %v", err)
	}

	err = Sign(pp, bobSK, m, muSig, pubkeys[:1])
	if err != nil {
		log.Fatalf("Bob sign failed: %v", err)
	}

	valid := Verify(pp, pubkeys, m, muSig)
	fmt.Println(valid)
	// Output:
	// true
}
