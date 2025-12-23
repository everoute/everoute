package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	ctlabels "github.com/everoute/ctlabels-go"
	numeric "github.com/everoute/numeric-go"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/errors"
)

var (
	humanOutput bool
)

var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "decode some formatted string",
}

var ctlabelsCmd = &cobra.Command{
	Use:   "ctlabels",
	Short: "decode ct labels from hex or binary string",
	Long: "decode ct labels from hex or binary string, " +
		"e.g. erctl decode ctlabels 0x0123456789abcdef or " +
		"erctl decode ctlabels 0b0000000100100011010001010110011110001001101010111100110111101111",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("ctlabels hex or binary string is required")
		}

		errs := lo.Map(args, func(label string, _ int) (err error) {
			defer func() {
				if p := recover(); p != nil {
					e, ok := p.(string)
					err = lo.If(ok, fmt.Errorf("parse %s: %s", label, e)).Else(fmt.Errorf("%v", p))
				}
			}()

			raw, err := parseLabelString(label)
			if err != nil {
				return fmt.Errorf("parse %s: %v", label, err)
			}

			scheme, info := lo.Must2(ctlabels.DecodeConntrackLabels(raw))
			if scheme == ctlabels.EncodingSchemeOld {
				info = lo.Must(ctlabels.DecodeMicroSegmentation(numeric.Uint128FromLittleEndianBytes(raw)))
			}

			if humanOutput {
				return printHumanFormat(cmd, label, scheme, info)
			}
			return printJSONFormat(cmd, label, scheme, info)
		})

		return errors.NewAggregate(errs)
	},
}

func parseLabelString(label string) ([]byte, error) {
	label = strings.TrimSpace(label)

	var isBinary bool
	var binStr string

	// Check if it's binary format (0b prefix or length-based detection)
	switch {
	case strings.HasPrefix(label, "0b"):
		isBinary = true
		binStr = strings.TrimPrefix(label, "0b")
	case strings.HasPrefix(label, "0x"):
		isBinary = false
	default:
		// No prefix, check by length and content
		// If length is 128 and contains only 0 and 1, treat as binary
		if len(label) == 128 {
			isBinary = true
			for _, c := range label {
				if c != '0' && c != '1' {
					isBinary = false
					break
				}
			}
		}
		if isBinary {
			binStr = label
		}
	}

	if isBinary {
		return parseBinaryString(binStr)
	}

	// Parse as hexadecimal
	formatedLabel := strings.TrimPrefix(label, "0x")
	formatedLabel = lo.If(len(formatedLabel) < 32, strings.Repeat("0", 32-len(formatedLabel))+formatedLabel).Else(formatedLabel)
	hexBytes, err := hex.DecodeString(formatedLabel)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %v", err)
	}
	return lo.ToPtr(numeric.Uint128FromBigEndianBytes(hexBytes)).Bytes(), nil
}

func parseBinaryString(binStr string) ([]byte, error) {
	// Pad to 128 bits (128 characters)
	if len(binStr) < 128 {
		binStr = strings.Repeat("0", 128-len(binStr)) + binStr
	} else if len(binStr) > 128 {
		return nil, fmt.Errorf("binary string too long: %d bits (max 128)", len(binStr))
	}

	// Convert binary string to bytes (big-endian)
	// Each byte is 8 bits, so we need 16 bytes for 128 bits
	bytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		start := i * 8
		end := start + 8
		if end > len(binStr) {
			end = len(binStr)
		}
		byteStr := binStr[start:end]
		val, err := strconv.ParseUint(byteStr, 2, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid binary string at byte %d: %v", i, err)
		}
		bytes[i] = byte(val)
	}

	return lo.ToPtr(numeric.Uint128FromBigEndianBytes(bytes)).Bytes(), nil
}

func printJSONFormat(cmd *cobra.Command, label string, scheme ctlabels.EncodingScheme, info any) error {
	e := json.NewEncoder(cmd.OutOrStdout())
	e.SetIndent("", "  ")
	return e.Encode(map[string]any{"label": label, "scheme": scheme, "info": info})
}

func printHumanFormat(cmd *cobra.Command, label string, scheme ctlabels.EncodingScheme, info any) error {
	_ = scheme
	fmt.Fprintf(cmd.OutOrStdout(), "label: %s\n", label)
	printHumanInfoStruct(cmd.OutOrStdout(), info, "")

	return nil
}

func formatEncodingScheme(scheme ctlabels.EncodingScheme) string {
	switch scheme {
	case ctlabels.EncodingSchemeOld:
		return "legacy"
	case ctlabels.EncodingSchemeTrafficVisualization:
		return "traffic visualization"
	case ctlabels.EncodingSchemeReserved:
		return "reserved"
	case ctlabels.EncodingSchemeMicroSegmentation:
		return "micro segmentation"
	default:
		return fmt.Sprintf("0x%02x", uint8(scheme))
	}
}

func formatPacketSource(source ctlabels.PacketSource) string {
	switch source {
	case ctlabels.PacketSourceLocalBridge:
		return "local bridge"
	case ctlabels.PacketSourceUplinkBridge:
		return "uplink bridge"
	default:
		return fmt.Sprintf("0x%02x", uint8(source))
	}
}

func formatFieldValue(fieldName string, value any) string {
	// Handle scheme and encoding_scheme fields
	if fieldName == "scheme" || fieldName == "encoding_scheme" {
		if scheme, ok := value.(ctlabels.EncodingScheme); ok {
			return formatEncodingScheme(scheme)
		}
		// Try to convert from numeric value
		if val := reflect.ValueOf(value); val.Kind() == reflect.Uint8 || val.Kind() == reflect.Uint || val.Kind() == reflect.Int {
			scheme := ctlabels.EncodingScheme(val.Uint())
			return formatEncodingScheme(scheme)
		}
	}

	// Handle packet_source fields
	if fieldName == "origin_packet_source" || fieldName == "reply_packet_source" {
		if source, ok := value.(ctlabels.PacketSource); ok {
			return formatPacketSource(source)
		}
		// Try to convert from numeric value
		if val := reflect.ValueOf(value); val.Kind() == reflect.Uint8 || val.Kind() == reflect.Uint || val.Kind() == reflect.Int {
			source := ctlabels.PacketSource(val.Uint())
			return formatPacketSource(source)
		}
	}

	// Handle inport fields - display as decimal
	if fieldName == "origin_inport" || fieldName == "reply_inport" {
		if val := reflect.ValueOf(value); val.IsValid() {
			switch val.Kind() {
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				return fmt.Sprintf("%d", val.Uint())
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				return fmt.Sprintf("%d", val.Int())
			}
		}
	}

	// Handle bool type
	if val := reflect.ValueOf(value); val.Kind() == reflect.Bool {
		return fmt.Sprintf("%t", val.Bool())
	}

	// Handle integer types - display as hex
	if val := reflect.ValueOf(value); val.IsValid() {
		switch val.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return fmt.Sprintf("0x%x", val.Uint())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return fmt.Sprintf("0x%x", uint64(val.Int()))
		}
	}

	// Fallback to string representation
	return fmt.Sprintf("%v", value)
}

func printHumanInfoStruct(out io.Writer, info any, prefix string) {
	if info == nil {
		return
	}

	val := reflect.ValueOf(info)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		// Fallback to JSON marshaling for non-struct types
		infoBytes, err := json.Marshal(info)
		if err == nil {
			var infoMap map[string]any
			if err := json.Unmarshal(infoBytes, &infoMap); err == nil {
				printHumanInfoMap(out, infoMap, prefix)
				return
			}
		}
		fmt.Fprintf(out, "%s%v\n", prefix, info)
		return
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldVal := val.Field(i)

		// Skip unexported fields
		if !fieldVal.CanInterface() {
			continue
		}

		fieldName := field.Name
		// Use json tag if available
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			if name, _, found := strings.Cut(jsonTag, ","); found {
				fieldName = name
			} else {
				fieldName = jsonTag
			}
		}

		value := fieldVal.Interface()
		formattedValue := formatFieldValue(fieldName, value)

		fmt.Fprintf(out, "%s%s: %s\n", prefix, fieldName, formattedValue)
	}
}

func printHumanInfoMap(out io.Writer, data map[string]any, prefix string) {
	for k, v := range data {
		switch val := v.(type) {
		case map[string]any:
			fmt.Fprintf(out, "%s%s:\n", prefix, k)
			printHumanInfoMap(out, val, prefix+"  ")
		case []any:
			fmt.Fprintf(out, "%s%s:\n", prefix, k)
			for i, item := range val {
				if itemMap, ok := item.(map[string]any); ok {
					fmt.Fprintf(out, "%s  [%d]:\n", prefix, i)
					printHumanInfoMap(out, itemMap, prefix+"    ")
				} else {
					formattedValue := formatFieldValue(k, item)
					fmt.Fprintf(out, "%s  [%d]: %s\n", prefix, i, formattedValue)
				}
			}
		default:
			formattedValue := formatFieldValue(k, v)
			fmt.Fprintf(out, "%s%s: %s\n", prefix, k, formattedValue)
		}
	}
}

func init() {
	rootCmd.AddCommand(decodeCmd)
	decodeCmd.AddCommand(ctlabelsCmd)
	ctlabelsCmd.Flags().BoolVarP(&humanOutput, "human", "H", false, "display in human-readable format")
}
