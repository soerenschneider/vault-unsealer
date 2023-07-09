package auth

import (
	"os"
	"testing"
)

func TestImplicitAuth_Authenticate_EnvVar(t *testing.T) {
	a := ImplicitAuth{}
	val := "my random vault token"
	os.Setenv("VAULT_TOKEN", val)
	defer os.Setenv("VAULT_TOKEN", "")
	got, err := a.Authenticate(nil)
	if err != nil {
		t.Fatal(err)
	}

	if got != val {
		t.Fatalf("expected %s, got %s", val, got)
	}
}

func TestImplicitAuth_Authenticate_File(t *testing.T) {
	// 1. Prepare
	file, err := os.CreateTemp("", "vault")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	val := "my random vault token"
	_ = os.WriteFile(file.Name(), []byte(val), 0644) // #nosec G306

	os.Setenv("VAULT_TOKEN", "")

	// 2. Test
	a := NewTokenImplicitAuth(file.Name())
	got, err := a.Authenticate(nil)
	if err != nil {
		t.Fatal(err)
	}

	if got != val {
		t.Fatalf("expected %s, got %s", val, got)
	}
}
