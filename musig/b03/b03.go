package b03

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

func SingleSign(_ *PublicParams, sk *PrivateKey, m []byte) *Signature {
	h := util.HashBytesToG1(m, nil)
	s := NewSignature()
	s.Sig.ScalarMult(sk.X, h)
	return s
}

func Aggregate(_ *PublicParams, sigs []*Signature) *Signature {
	muSig := NewSignature()

	for _, sig := range sigs {
		muSig.Sig.Add(sig.Sig, muSig.Sig)
	}

	return muSig
}

func Sign(pp *PublicParams, sk *PrivateKey, m []byte, muSig *Signature) error {
	sig := SingleSign(pp, sk, m)
	muSig.Sig.Add(sig.Sig, muSig.Sig)
	return nil
}

func Verify(pp *PublicParams, pubkeys []*PublicKey, m []byte, sig *Signature) bool {
	aggPK := util.NewG2Identity()
	for _, pk := range pubkeys {
		aggPK.Add(pk.V, aggPK)
	}

	h := util.HashBytesToG1(m, nil)
	expect := bls.Pair(h, aggPK)

	got := bls.Pair(sig.Sig, pp.G2)

	return got.IsEqual(expect)
}
