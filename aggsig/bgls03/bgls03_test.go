package bgls03

import (
	"fmt"
)

func Example() {
	aliceMsg := []byte("Alice's message")
	bobMsg := []byte("Bob's message")
	carolMsg := []byte("Carol's message")
	msgs := [][]byte{aliceMsg, bobMsg, carolMsg}

	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	carolPK, carolSK := KeyGen(pp)
	pubkeys := []*PublicKey{alicePK, bobPK, carolPK}

	aliceSig := Sign(pp, aliceSK, aliceMsg)
	bobSig := Sign(pp, bobSK, bobMsg)
	carolSig := Sign(pp, carolSK, carolMsg)

	sigs := []*Signature{aliceSig, bobSig, carolSig}
	aggSig := Aggregate(pp, sigs)

	valid := AggregateVerify(pp, pubkeys, msgs, aggSig)
	fmt.Println(valid)
	// Output:
	// true
}
