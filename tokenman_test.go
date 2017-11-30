package tokenman

import "testing"

func TestCreateAndVerifyToken(t *testing.T) {
	tm, err := NewTokenMan("1234")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tm.CreateToken("tester", 1)
	if err != nil {
		t.Fatalf("%#v:%v", tok, err)
	}
	at, err := tm.VerifyToken(tok)
	if err != nil {
		t.Fatalf("%#v\n%#v\n:%v", tok, at, err)
	}
	if at.Issuer != ClaimIssuer {
		t.Error("expected value of ClaimAudience")
	}
	if at.Identity != "tester" {
		t.Error("expected tester")
	}
	t.Logf("%s\n%#v", tok, at)
}
