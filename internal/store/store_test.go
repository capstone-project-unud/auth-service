package store

import "testing"

func TestSessionDigest(t *testing.T) {
	expected := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if HashToken("abc") != expected {
		t.Fatal("unexpected SHA-256 digest")
	}
	if HashToken("different") == HashToken("abc") {
		t.Fatal("different sessions share digest")
	}
}
