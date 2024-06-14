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
		leafHashes = append(leafHashes, *(*Hash)(hashAlgo.Sum(nil)))
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
	otherHash := *(*Hash)(hashAlgo.Sum([]byte{byte('A')}))
	if mt.IsIncluded(otherHash) {
		t.Error("should NOT include leaf hash: ", otherHash)
	}

	reverseLeafHashes := make([]Hash, 0)
	for d := '9'; d >= '0'; d-- {
		hashAlgo := sha3.NewLegacyKeccak256()
		hashAlgo.Write([]byte{byte(d)})
		reverseLeafHashes = append(reverseLeafHashes, *(*Hash)(hashAlgo.Sum(nil)))
	}
	reverseMt, err := NewMerkleTree(reverseLeafHashes)
	checkErr(err, t)
	reverseRoot := reverseMt.RootHash()
	t.Log("reverse root hash: ", reverseRoot)

	if root == reverseRoot {
		t.Error("root should not be same as reverse root")
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
	if Verify(proof, Hash(reverseRoot), leafHashes[2]) {
		t.Error("should not verify for leaf and root: ", leafHashes[2], reverseRoot)
	}
}

func TestChar(t *testing.T) {
	leafHashes := make([]Hash, 0)
	for d := 'a'; d <= 'z'; d++ {
		hashAlgo := sha3.NewLegacyKeccak256()
		hashAlgo.Write([]byte{byte(d)})
		leafHashes = append(leafHashes, *(*Hash)(hashAlgo.Sum(nil)))
	}
	for d := 'A'; d <= 'Z'; d++ {
		hashAlgo := sha3.NewLegacyKeccak256()
		hashAlgo.Write([]byte{byte(d)})
		leafHashes = append(leafHashes, *(*Hash)(hashAlgo.Sum(nil)))
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
	if mt.IsIncluded(*(*Hash)(otherHash)) {
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
	if Verify(proof, *(*Hash)(otherHash), leafHashes[3]) {
		t.Error("should not verify for leaf and root: ", leafHashes[3], otherHash)
	}

	if !Verify(proof[1:], root, CommutativeHash(leafHashes[3], proof[0])) {
		t.Error("should verify: leaf proof[0]: ", leafHashes[3], proof[0])
	}
}
