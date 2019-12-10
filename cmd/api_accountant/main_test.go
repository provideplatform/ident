package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestIdentAPIAccountant(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ident API Accountant Suite")
}

var _ = Describe("Main", func() {

})
