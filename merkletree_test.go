package merkletree

import (
	"testing"

	"golang.org/x/crypto/sha3"
)

func checkErr(err error, t *testing.T) {
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDigit(t *testing.T) {
	leafHashes := make([]Hash, 0)
	for d := '0'; d <= '9'; d++ {
		hashAlgo := sha3.NewLegacyKeccak256()
		hashAlgo.Write([]byte{byte(d)})
		leafHashes = append(leafHashes, Hash(hashAlgo.Sum(nil)))
	}
	mt, err := NewMerkleTree(leafHashes)
	checkErr(err, t)
	root := mt.RootHash()
	t.Log("root hash: ", root)
	for _, lh := range leafHashes {
		if !mt.IsIncluded(lh) {
			t.Error("should include: ", lh)
		}
	}
	hashAlgo := sha3.NewLegacyKeccak256()
	otherHash := hashAlgo.Sum([]byte{byte('A')})
	if mt.IsIncluded(Hash(otherHash)) {
		t.Error("should NOT include: ", otherHash)
	}
	for _, lh := range leafHashes {
		proof, err := mt.GetProof(lh)
		checkErr(err, t)
		if !Verify(proof, root, lh) {
			t.Error("verify fails for leaf: ", lh)
		}
	}
	proof, err := mt.GetProof(leafHashes[2])
	checkErr(err, t)
	if Verify(proof, Hash(otherHash), leafHashes[2]) {
		t.Error("should not verify for leaf and root: ", leafHashes[2], otherHash)
	}
}

func TestChar(t *testing.T) {
	leafHashes := make([]Hash, 0)
	for d := 'a'; d <= 'z'; d++ {
		hashAlgo := sha3.NewLegacyKeccak256()
		hashAlgo.Write([]byte{byte(d)})
		leafHashes = append(leafHashes, Hash(hashAlgo.Sum(nil)))
	}
	for d := 'A'; d <= 'Z'; d++ {
		hashAlgo := sha3.NewLegacyKeccak256()
		hashAlgo.Write([]byte{byte(d)})
		leafHashes = append(leafHashes, Hash(hashAlgo.Sum(nil)))
	}
	mt, err := NewMerkleTree(leafHashes)
	checkErr(err, t)
	root := mt.RootHash()
	t.Log("root hash: ", root)
	for _, lh := range leafHashes {
		if !mt.IsIncluded(lh) {
			t.Error("should include: ", lh)
		}
	}
	hashAlgo := sha3.NewLegacyKeccak256()
	otherHash := hashAlgo.Sum([]byte{byte('6')})
	if mt.IsIncluded(Hash(otherHash)) {
		t.Error("should NOT include: ", otherHash)
	}
	for _, lh := range leafHashes {
		proof, err := mt.GetProof(lh)
		checkErr(err, t)
		if !Verify(proof, root, lh) {
			t.Error("verify fails for leaf: ", lh)
		}
	}
	proof, err := mt.GetProof(leafHashes[3])
	checkErr(err, t)
	if Verify(proof, Hash(otherHash), leafHashes[3]) {
		t.Error("should not verify for leaf and root: ", leafHashes[3], otherHash)
	}
}
