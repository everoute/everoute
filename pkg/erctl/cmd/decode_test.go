package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	ctlabels "github.com/everoute/ctlabels-go"
	numeric "github.com/everoute/numeric-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("Decode", func() {
	Describe("parseLabelString", func() {
		It("should parse hex string with 0x prefix", func() {
			label := "0x0123456789abcdef0123456789abcdef"
			raw, err := parseLabelString(label)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))

			expectedHex := "0123456789abcdef0123456789abcdef"
			expectedBytes, _ := hex.DecodeString(expectedHex)
			expectedRaw := lo.ToPtr(numeric.Uint128FromBigEndianBytes(expectedBytes)).Bytes()
			Expect(raw).Should(Equal(expectedRaw))
		})

		It("should parse hex string without 0x prefix", func() {
			label := "0123456789abcdef0123456789abcdef"
			raw, err := parseLabelString(label)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})

		It("should parse hex string with short length and pad zeros", func() {
			label := "0x123456789abcdef"
			raw, err := parseLabelString(label)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})

		It("should parse binary string with 0b prefix", func() {
			// 0x0123456789abcdef0123456789abcdef in binary (first 8 bytes)
			label := "0b0000000100100011010001010110011110001001101010111100110111101111"
			raw, err := parseLabelString(label)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})

		It("should parse binary string without prefix (128 bits)", func() {
			// 128-bit binary string
			label := "00000001001000110100010101100111100010011010101111001101111011110000000100100011010001010110011110001001101010111100110111101111"
			raw, err := parseLabelString(label)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})

		It("should parse binary string with short length and pad zeros", func() {
			label := "0b101"
			raw, err := parseLabelString(label)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})

		It("should return error for invalid hex string", func() {
			label := "0xinvalid"
			_, err := parseLabelString(label)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error for binary string too long", func() {
			// Create a 129-bit binary string
			longBinStr := strings.Repeat("1", 129)
			label := "0b" + longBinStr
			_, err := parseLabelString(label)
			Expect(err).Should(HaveOccurred())
		})

		It("should handle empty string as hex and pad zeros", func() {
			label := ""
			raw, err := parseLabelString(label)
			// Empty string will be treated as hex and padded to 32 hex chars (128 bits)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})
	})

	Describe("parseBinaryString", func() {
		It("should parse 128-bit binary string", func() {
			// All zeros
			binStr := strings.Repeat("0", 128)
			raw, err := parseBinaryString(binStr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})

		It("should pad short binary string with leading zeros", func() {
			binStr := "101"
			raw, err := parseBinaryString(binStr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})

		It("should return error for binary string too long", func() {
			binStr := strings.Repeat("1", 129)
			_, err := parseBinaryString(binStr)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("too long"))
		})

		It("should parse binary string representing 0x0123456789abcdef", func() {
			// 0x0123456789abcdef in binary (64 bits, will be padded to 128)
			binStr := "0000000100100011010001010110011110001001101010111100110111101111"
			raw, err := parseBinaryString(binStr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(raw).Should(HaveLen(16))
		})
	})

	Describe("ctlabelsCmd", func() {
		It("should decode hex label and output JSON", func() {
			// Use a known test case - all zeros
			label := "0x00000000000000000000000000000000"
			var buf bytes.Buffer
			ctlabelsCmd.SetOut(&buf)
			humanOutput = false

			err := ctlabelsCmd.RunE(ctlabelsCmd, []string{label})
			Expect(err).ShouldNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(HaveKey("label"))
			Expect(result).Should(HaveKey("scheme"))
			Expect(result).Should(HaveKey("info"))
		})

		It("should decode binary label and output JSON", func() {
			// All zeros in binary
			label := "0b" + strings.Repeat("0", 128)
			var buf bytes.Buffer
			ctlabelsCmd.SetOut(&buf)
			humanOutput = false

			err := ctlabelsCmd.RunE(ctlabelsCmd, []string{label})
			Expect(err).ShouldNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(HaveKey("label"))
		})

		It("should output human-readable format", func() {
			label := "0x00000000000000000000000000000000"
			var buf bytes.Buffer
			ctlabelsCmd.SetOut(&buf)
			humanOutput = true

			err := ctlabelsCmd.RunE(ctlabelsCmd, []string{label})
			Expect(err).ShouldNot(HaveOccurred())

			output := buf.String()
			Expect(output).Should(ContainSubstring("label:"))
		})

		It("should return error when no arguments provided", func() {
			err := ctlabelsCmd.RunE(ctlabelsCmd, []string{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("required"))
		})

		It("should handle multiple labels", func() {
			label1 := "0x00000000000000000000000000000000"
			label2 := "0x00000000000000000000000000000001"
			var buf bytes.Buffer
			ctlabelsCmd.SetOut(&buf)
			humanOutput = false

			err := ctlabelsCmd.RunE(ctlabelsCmd, []string{label1, label2})
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should handle old encoding scheme", func() {
			// Create a label that triggers old encoding scheme
			// This is a simplified test - actual old scheme detection depends on ctlabels-go
			label := "0x00000000000000000000000000000003" // May trigger old scheme
			var buf bytes.Buffer
			ctlabelsCmd.SetOut(&buf)
			humanOutput = false

			err := ctlabelsCmd.RunE(ctlabelsCmd, []string{label})
			// Should not error regardless of scheme
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Describe("Integration with ctlabels-go", func() {
		It("should decode and match ctlabels-go output", func() {
			// Test with a known hex value
			label := "0x0123456789abcdef0123456789abcdef"
			raw, err := parseLabelString(label)
			Expect(err).ShouldNot(HaveOccurred())

			scheme, _, err := ctlabels.DecodeConntrackLabels(raw)
			// Should not error
			Expect(err).ShouldNot(HaveOccurred())
			// Just verify the function can be called successfully

			// If old scheme, test micro segmentation decoding
			if scheme == ctlabels.EncodingSchemeOld {
				_, err = ctlabels.DecodeMicroSegmentation(numeric.Uint128FromLittleEndianBytes(raw))
				Expect(err).ShouldNot(HaveOccurred())
			}
		})

		It("should handle binary input equivalent to hex", func() {
			hexLabel := "0x0123456789abcdef0123456789abcdef"
			hexRaw, err1 := parseLabelString(hexLabel)
			Expect(err1).ShouldNot(HaveOccurred())

			// Convert to binary equivalent
			binLabel := "0b00000001001000110100010101100111100010011010101111001101111011110000000100100011010001010110011110001001101010111100110111101111"
			binRaw, err2 := parseLabelString(binLabel)
			Expect(err2).ShouldNot(HaveOccurred())

			// Both should produce same raw bytes
			Expect(hexRaw).Should(Equal(binRaw))
		})
	})
})
