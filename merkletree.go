package merkletree

import (
	"errors"

	"golang.org/x/crypto/sha3"
)

type Hash [32]byte

type MerkleTree struct {
	nodeHashes      [][]Hash
	leafHashToIndex map[Hash]int
}

var ErrDuplicateLeaves = errors.New("duplicate leaf hash values")
var ErrEmptyLeafArray = errors.New("empty leaf hash array")
var ErrLeafNotExist = errors.New("leaf not exist")

func CompareHash(a, b Hash) int {
	for i := 0; i < 32; i++ {
		if a[i] > b[i] {
			return 1
		} else if a[i] < b[i] {
			return -1
		}
	}
	return 0
}

func CommutativeHash(a, b Hash) Hash {
	hashAlgo := sha3.NewLegacyKeccak256()
	if CompareHash(a, b) < 0 {
		hashAlgo.Write(a[:])
		hashAlgo.Write(b[:])
	} else {
		hashAlgo.Write(b[:])
		hashAlgo.Write(a[:])
	}
	return Hash(hashAlgo.Sum(nil))
}

func NewMerkleTree(leaveHashes []Hash) (*MerkleTree, error) {
	if len(leaveHashes) == 0 {
		return nil, ErrEmptyLeafArray
	}
	//check redundant leaves
	leafHashToIndex := make(map[Hash]int)
	for li, lh := range leaveHashes {
		_, exists := leafHashToIndex[lh]
		if exists {
			return nil, ErrDuplicateLeaves
		}
		leafHashToIndex[lh] = li
	}
	//create merkle tree
	nodeHashes := make([][]Hash, 0)
	n := len(leaveHashes)
	levelHashes := make([]Hash, n)
	copy(levelHashes, leaveHashes)
	for n > 0 {
		nodeHashes = append(nodeHashes, levelHashes)
		if n == 1 {
			break
		}
		//compute next upper level node hashes
		nOdd := n%2 == 1
		newN := (n + 1) / 2
		newLevelHashes := make([]Hash, newN)
		for i := 0; i < newN; i++ {
			if nOdd && i == newN-1 {
				//concat self
				newLevelHashes[i] = CommutativeHash(levelHashes[2*i], levelHashes[2*i])
			} else {
				newLevelHashes[i] = CommutativeHash(levelHashes[2*i], levelHashes[2*i+1])
			}
		}
		n = newN
		levelHashes = newLevelHashes
	}

	return &MerkleTree{nodeHashes, leafHashToIndex}, nil
}

func (mt *MerkleTree) IsIncluded(leafHash Hash) bool {
	_, exists := mt.leafHashToIndex[leafHash]
	return exists
}

func (mt *MerkleTree) RootHash() Hash {
	height := len(mt.nodeHashes)
	return mt.nodeHashes[height-1][0]
}

func (mt *MerkleTree) GetProof(leafHash Hash) ([]Hash, error) {
	index, exists := mt.leafHashToIndex[leafHash]
	if !exists {
		return nil, ErrLeafNotExist
	}
	height := len(mt.nodeHashes)
	proof := make([]Hash, height-1)
	for i := 0; i < height-1; i++ {
		n := len(mt.nodeHashes[i])
		sib := sibling(index, n)
		proof[i] = mt.nodeHashes[i][sib]
		index = index / 2
	}
	return proof, nil
}

func sibling(index, length int) int {
	if length%2 == 1 && index == length-1 {
		return index
	}
	if index%2 == 0 {
		return index + 1
	}
	return index - 1
}

func ProcessProof(proof []Hash, leaf Hash) Hash {
	computedHash := leaf
	for _, p := range proof {
		computedHash = CommutativeHash(computedHash, p)
	}
	return computedHash
}

func Verify(proof []Hash, root, leaf Hash) bool {
	return ProcessProof(proof, leaf) == root
}
