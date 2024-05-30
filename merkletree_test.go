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
	for _, lh := range leafHashes {
		proof, err := mt.GetProof(lh)
		checkErr(err, t)
		if !Verify(proof, root, lh) {
			t.Error("verify fails for leaf: ", lh)
		}
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
	for _, lh := range leafHashes {
		proof, err := mt.GetProof(lh)
		checkErr(err, t)
		if !Verify(proof, root, lh) {
			t.Error("verify fails for leaf: ", lh)
		}
	}
}
