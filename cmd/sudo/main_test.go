package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestIdentSudo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ident Sudo Suite")
}

var _ = Describe("Main", func() {

})
