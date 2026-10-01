package bip39

import (
	_ "embed"
	"strings"

	"github.com/FortegoSwiss/codebook-cipher/wordlist"
)

//go:embed wordlist.txt
var englishWordlist string

var english = mustEnglishList()

// English returns the canonical 2,048-word English BIP-39 word list as a
// validated wordlist.List. The list is fixed and embedded in this package,
// and validated once at package initialisation.
func English() wordlist.List {
	return english
}

func mustEnglishList() wordlist.List {
	words := strings.Split(strings.TrimRight(englishWordlist, "\n"), "\n")
	v, err := wordlist.New(words)
	if err != nil {
		panic("wordlist/bip39: embedded canonical English word list failed validation: " + err.Error())
	}
	return v
}
