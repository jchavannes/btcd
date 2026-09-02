// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jchavannes/btcd/chaincfg"
	"github.com/jchavannes/btcd/wire"
	"github.com/jchavannes/btcutil"
)

// Token prefix building blocks for the tests below.  The layout is
// OP_PREFIXTOKEN <category 32 bytes> <bitfield> [commitment] [amount].
const (
	tokenCategory = "0000000000000000000000000000000000000000000000000000000000000001"
	tokenP2PKH    = "76a914" + tokenPkHash + "88ac"
	tokenP2SH     = "a914" + tokenPkHash + "87"
	tokenPkHash   = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba"
)

func tokenScript(prefix, locking string) []byte {
	return hexToBytes("ef" + tokenCategory + prefix + locking)
}

func tokenAddress(t *testing.T, pkHash string) btcutil.Address {
	addr, err := btcutil.NewAddressPubKeyHash(hexToBytes(pkHash),
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}
	return addr
}

func tokenScriptAddress(t *testing.T, scriptHash string) btcutil.Address {
	addr, err := btcutil.NewAddressScriptHashFromHash(hexToBytes(scriptHash),
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewAddressScriptHashFromHash: %v", err)
	}
	return addr
}

// validTokenPrefixes are well-formed prefixes (bitfield and optional
// commitment and amount) covering each combination the spec allows.
var validTokenPrefixes = []struct {
	name   string
	prefix string
}{
	{"fungible amount 1", "10" + "01"},
	{"fungible amount 0xfd encoded", "10" + "fde803"},
	{"fungible amount 0xfe encoded", "10" + "fe00e1f505"},
	{"fungible max amount 0xff encoded", "10" + "ffffffffffffffff7f"},
	{"immutable nft no commitment", "20"},
	{"mutable nft with commitment", "61" + "02" + "abcd"},
	{"minting nft with commitment and amount", "72" + "03" + "010203" + "fde803"},
}

func TestExtractPkScriptAddrsCashToken(t *testing.T) {
	t.Parallel()

	for _, test := range validTokenPrefixes {
		script := tokenScript(test.prefix, tokenP2PKH)
		class, addrs, reqSigs, err := ExtractPkScriptAddrs(script,
			&chaincfg.MainNetParams)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", test.name, err)
			continue
		}
		if class != PubKeyHashTy {
			t.Errorf("%s: class %v, want %v", test.name, class, PubKeyHashTy)
		}
		if reqSigs != 1 {
			t.Errorf("%s: reqSigs %d, want 1", test.name, reqSigs)
		}
		want := tokenAddress(t, tokenPkHash)
		if len(addrs) != 1 || addrs[0].String() != want.String() {
			t.Errorf("%s: addrs %v, want [%v]", test.name, addrs, want)
		}
	}

	script := tokenScript("10"+"01", tokenP2SH)
	class, addrs, reqSigs, err := ExtractPkScriptAddrs(script,
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("p2sh: unexpected error: %v", err)
	}
	want := tokenScriptAddress(t, tokenPkHash)
	if class != ScriptHashTy || reqSigs != 1 || len(addrs) != 1 ||
		addrs[0].String() != want.String() {
		t.Errorf("p2sh: got class %v addrs %v reqSigs %d, want %v [%v] 1",
			class, addrs, reqSigs, ScriptHashTy, want)
	}
}

func TestCashTokenPrefixRoundTrip(t *testing.T) {
	t.Parallel()

	for _, test := range validTokenPrefixes {
		script := tokenScript(test.prefix, tokenP2PKH)
		pops, err := parseScript(script)
		if err != nil {
			t.Errorf("%s: parse: %v", test.name, err)
			continue
		}
		if pops[0].opcode.value != OP_PREFIXTOKEN {
			t.Errorf("%s: first opcode %s, want OP_PREFIXTOKEN",
				test.name, pops[0].opcode.name)
		}
		wantData := hexToBytes(tokenCategory + test.prefix)
		if !bytes.Equal(pops[0].data, wantData) {
			t.Errorf("%s: prefix data %x, want %x", test.name,
				pops[0].data, wantData)
		}
		// The locking script must parse as the usual P2PKH opcodes.
		if len(pops) != 6 {
			t.Errorf("%s: parsed %d opcodes, want 6", test.name, len(pops))
		}
		unparsed, err := unparseScript(pops)
		if err != nil {
			t.Errorf("%s: unparse: %v", test.name, err)
			continue
		}
		if !bytes.Equal(unparsed, script) {
			t.Errorf("%s: unparsed %x, want %x", test.name, unparsed, script)
		}
	}
}

func TestCashTokenDisasm(t *testing.T) {
	t.Parallel()

	script := tokenScript("10"+"01", tokenP2PKH)
	disasm, err := DisasmString(script)
	if err != nil {
		t.Fatalf("DisasmString: %v", err)
	}
	want := "[OP_PREFIXTOKEN " + tokenCategory + "1001] OP_DUP OP_HASH160 " +
		tokenPkHash + " OP_EQUALVERIFY OP_CHECKSIG"
	if disasm != want {
		t.Errorf("disasm:\n got %s\nwant %s", disasm, want)
	}
	pops, err := parseScript(script)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want = "OP_PREFIXTOKEN " + tokenCategory + "1001"
	if got := pops[0].print(false); got != want {
		t.Errorf("multiline print %q, want %q", got, want)
	}
}

// TestCashTokenNonLeadingPrefixByte ensures 0xef is only treated as the token
// prefix at offset 0; elsewhere it is an ordinary one-byte invalid opcode.
func TestCashTokenNonLeadingPrefixByte(t *testing.T) {
	t.Parallel()

	// OP_IF 0xef OP_ELSE OP_1 OP_ENDIF, as in script_tests.json.
	conditional := hexToBytes("63ef675168")
	pops, err := parseScript(conditional)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pops) != 5 || pops[1].opcode.value != OP_PREFIXTOKEN ||
		pops[1].opcode.length != 1 || len(pops[1].data) != 0 {
		t.Fatalf("parsed %d opcodes, want 5 with a bare OP_PREFIXTOKEN "+
			"second", len(pops))
	}
	unparsed, err := unparseScript(pops)
	if err != nil || !bytes.Equal(unparsed, conditional) {
		t.Errorf("unparse %x err %v, want %x", unparsed, err, conditional)
	}
	disasm, err := DisasmString(conditional)
	if err != nil {
		t.Fatalf("DisasmString: %v", err)
	}
	if want := "OP_IF OP_PREFIXTOKEN OP_ELSE 1 OP_ENDIF"; disasm != want {
		t.Errorf("disasm %q, want %q", disasm, want)
	}

	// Executing the 0xef branch must fail as a reserved opcode, while
	// skipping it must succeed.
	for _, test := range []struct {
		sigScript []byte
		errCode   ErrorCode
		ok        bool
	}{
		{[]byte{OP_0}, 0, true},
		{[]byte{OP_1}, ErrReservedOpcode, false},
	} {
		tx := &wire.MsgTx{TxIn: []*wire.TxIn{{SignatureScript: test.sigScript}}}
		vm, err := NewEngine(conditional, tx, 0, ScriptBip16, nil, 0)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		err = vm.Execute()
		if test.ok && err != nil {
			t.Errorf("sigScript %x: unexpected error %v", test.sigScript, err)
		}
		if !test.ok && !IsErrorCode(err, test.errCode) {
			t.Errorf("sigScript %x: error %v, want %v", test.sigScript, err,
				test.errCode)
		}
	}

	// A well-formed prefix that is not at offset 0 is bytecode, so it is
	// neither consumed nor stripped for address extraction.
	shifted := append([]byte{OP_NOP}, tokenScript("10"+"01", tokenP2PKH)...)
	pops, err = parseScript(shifted)
	if err != nil {
		t.Fatalf("parse shifted: %v", err)
	}
	if pops[1].opcode.value != OP_PREFIXTOKEN || len(pops[1].data) != 0 {
		t.Errorf("shifted 0xef parsed with %d data bytes, want 0",
			len(pops[1].data))
	}
	class, addrs, _, err := ExtractPkScriptAddrs(shifted, &chaincfg.MainNetParams)
	if err != nil || class != NonStandardTy || len(addrs) != 0 {
		t.Errorf("shifted: class %v addrs %v err %v, want nonstandard, none, nil",
			class, addrs, err)
	}

	// A leading prefix followed by bytecode that itself contains 0xef.
	nested := tokenScript("10"+"01", "63ef675168")
	pops, err = parseScript(nested)
	if err != nil {
		t.Fatalf("parse nested: %v", err)
	}
	if len(pops) != 6 || pops[0].opcode.length != -5 || pops[2].opcode.length != 1 {
		t.Errorf("nested parsed %d opcodes, want 6 with only the first "+
			"carrying token data", len(pops))
	}
	unparsed, err = unparseScript(pops)
	if err != nil || !bytes.Equal(unparsed, nested) {
		t.Errorf("nested unparse %x err %v, want %x", unparsed, err, nested)
	}
}

func TestCashTokenPrefixMalformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script string
	}{
		{"prefix only", "ef"},
		{"truncated category", "ef" + tokenCategory[:20]},
		{"missing bitfield", "ef" + tokenCategory},
		{"reserved bit set", "ef" + tokenCategory + "90" + "01"},
		{"neither nft nor amount", "ef" + tokenCategory + "00"},
		{"capability without nft", "ef" + tokenCategory + "11" + "01"},
		{"commitment without nft", "ef" + tokenCategory + "50" + "01" + "aa" + "01"},
		{"capability out of range", "ef" + tokenCategory + "23"},
		{"missing commitment length", "ef" + tokenCategory + "60"},
		{"zero commitment length", "ef" + tokenCategory + "60" + "00"},
		{"commitment longer than script", "ef" + tokenCategory + "60" + "05" + "0102"},
		{"commitment length past end", "ef" + tokenCategory + "60" + "fd"},
		{"non-minimal commitment length", "ef" + tokenCategory + "60" + "fd0100" + "aa"},
		{"missing amount", "ef" + tokenCategory + "10"},
		{"zero amount", "ef" + tokenCategory + "10" + "00"},
		{"amount past end", "ef" + tokenCategory + "10" + "ff01020304"},
		{"non-minimal amount", "ef" + tokenCategory + "10" + "fd0100"},
		{"amount above max", "ef" + tokenCategory + "10" + "ff0000000000000080"},
	}
	for _, test := range tests {
		script, err := hex.DecodeString(test.script)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", test.name, err)
		}
		if _, err := parseScript(script); !IsErrorCode(err, ErrMalformedPush) {
			t.Errorf("%s: parse error %v, want %v", test.name, err,
				ErrMalformedPush)
		}
		class, addrs, _, err := ExtractPkScriptAddrs(script,
			&chaincfg.MainNetParams)
		if err == nil || class != NonStandardTy || len(addrs) != 0 {
			t.Errorf("%s: ExtractPkScriptAddrs got class %v addrs %v "+
				"err %v, want nonstandard with error", test.name, class,
				addrs, err)
		}
	}
}
