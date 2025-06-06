package bgls

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/blschemes/util"
)

type PublicParams struct {
	G1 *bls.G1
	G2 *bls.G2
}

func NewPublicParams() *PublicParams {
	pp := new(PublicParams)
	pp.G1 = bls.G1Generator()
	pp.G2 = bls.G2Generator()
	return pp
}

type PrivateKey struct {
	X *bls.Scalar
}

type PublicKey struct {
	V *bls.G2
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	sk := new(PrivateKey)
	pk := new(PublicKey)

	sk.X = util.NewRandomScalar()
	pk.V = new(bls.G2)
	pk.V.ScalarMult(sk.X, pp.G2)

	return pk, sk
}

type Signature struct {
	Sig *bls.G1
}

func NewSignature() *Signature {
	sig := new(Signature)
	sig.Sig = util.NewG1Identity()
	return sig
}

func Sign(_ *PublicParams, sk *PrivateKey, m []byte) *Signature {
	h := util.HashBytesToG1(m, nil)
	s := NewSignature()
	s.Sig.ScalarMult(sk.X, h)
	return s
}

// NB: messages must all be distinct
func Aggregate(_ *PublicParams, sigs []*Signature) *Signature {
	aggSig := NewSignature()

	for _, sig := range sigs {
		aggSig.Sig.Add(sig.Sig, aggSig.Sig)
	}

	return aggSig
}

func AggregateVerify(pp *PublicParams, pubkeys []*PublicKey, msgs [][]byte, aggSig *Signature) bool {
	// TODO: ensure messages are all distinct, and reject otherwise

	expect := util.NewGtIdentity()
	for i := 0; i < len(pubkeys); i++ {
		pk := pubkeys[i]
		m := msgs[i]
		h := util.HashBytesToG1(m, nil)

		expect.Mul(bls.Pair(h, pk.V), expect)
	}

	got := bls.Pair(aggSig.Sig, pp.G2)

	return got.IsEqual(expect)
}
