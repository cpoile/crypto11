// Fixture provisioning is operator/test work, never part of KMD.
package main

import (
	crypto11 "github.com/eclipse-keypont/crypto11"
	"github.com/miekg/pkcs11"
	"os"
)

func main() {
	c, err := crypto11.ConfigureFromFile(os.Args[1])
	if err != nil {
		panic("fixture configure failed")
	}
	defer c.Close()
	if len(os.Args) == 3 {
		keys, err := c.FindKeys(nil, []byte("permitted"))
		if err != nil || len(keys) != 1 {
			panic("fixture target missing")
		}
		if keys[0].Delete() != nil {
			panic("fixture deletion failed")
		}
		if os.Args[2] == "replace" {
			generate(c, "permitted", "replacement", 256, nil)
		} else if os.Args[2] != "remove" {
			panic("invalid fixture action")
		}
		return
	}
	for _, label := range []string{"permitted", "sibling", "rejected", "no-decrypt", "extractable", "not-sensitive", "short", "duplicate", "duplicate"} {
		attrs := map[uint]interface{}{}
		bits := 256
		switch label {
		case "rejected":
			attrs[pkcs11.CKA_ENCRYPT] = false
		case "no-decrypt":
			attrs[pkcs11.CKA_DECRYPT] = false
		case "extractable":
			attrs[pkcs11.CKA_EXTRACTABLE] = true
		case "not-sensitive":
			attrs[pkcs11.CKA_SENSITIVE] = false
		case "short":
			bits = 128
		}
		generate(c, label, label, bits, attrs)
	}
}
func generate(c *crypto11.Context, label, id string, bits int, values map[uint]interface{}) {
	attrs, err := crypto11.NewAttributeSetWithIDAndLabel([]byte(id), []byte(label))
	if err != nil {
		panic("fixture attributes failed")
	}
	for typ, value := range values {
		if attrs.Set(typ, value) != nil {
			panic("fixture permissions failed")
		}
	}
	if _, err := c.GenerateSecretKeyWithAttributes(attrs, bits, crypto11.CipherAES); err != nil {
		panic("fixture key generation failed")
	}
}
