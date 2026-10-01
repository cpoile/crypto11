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
	for _, label := range []string{"permitted", "rejected"} {
		attrs, err := crypto11.NewAttributeSetWithIDAndLabel([]byte(label), []byte(label))
		if err != nil {
			panic("fixture attributes failed")
		}
		if err = attrs.Set(pkcs11.CKA_ENCRYPT, label == "permitted"); err != nil {
			panic("fixture permissions failed")
		}
		if _, err = c.GenerateSecretKeyWithAttributes(attrs, 256, crypto11.CipherAES); err != nil {
			panic("fixture key generation failed")
		}
	}
}
