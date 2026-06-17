package cmd

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	numeric "github.com/everoute/numeric-go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	ctmgr "github.com/everoute/everoute/pkg/agent/datapath/conntrack"
)

const (
	conntrackFamilyAll  = "all"
	conntrackFamilyIPv4 = "ipv4"
	conntrackFamilyIPv6 = "ipv6"
	conntrackMaxUint16  = 1<<16 - 1
)

type conntrackFilterOptions struct {
	family       string
	protocol     string
	zone         int
	origSrcIP    string
	origDstIP    string
	origSrcPort  int
	origDstPort  int
	replySrcIP   string
	replyDstIP   string
	replySrcPort int
	replyDstPort int
}

type conntrackDumpOptions struct {
	matchersFile string
	decode       bool
}

type conntrackDeleteOptions struct {
	matchersFile string
	all          bool
}

type conntrackMatcher struct {
	zone        *uint16
	flowMatcher ctmgr.FlowMatcher
}

func (m *conntrackMatcher) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if m == nil {
		return true
	}
	if m.zone != nil && flow.Zone != *m.zone {
		return false
	}
	return m.flowMatcher.MatchConntrackFlow(flow)
}

type conntrackMultiMatcher struct {
	matchers []ctmgr.Matcher
}

func (m *conntrackMultiMatcher) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if m == nil {
		return true
	}
	for i := range m.matchers {
		if m.matchers[i] != nil && m.matchers[i].MatchConntrackFlow(flow) {
			return true
		}
	}
	return false
}

type conntrackRuleFile struct {
	All  conntrackRuleFileMatcherList `toml:"all"`
	IPv4 conntrackRuleFileMatcherList `toml:"ipv4"`
	IPv6 conntrackRuleFileMatcherList `toml:"ipv6"`
}

type conntrackRuleFileMatcherList struct {
	Matchers []conntrackRuleFileMatcher `toml:"matchers"`
}

type conntrackRuleFileMatcher struct {
	Protocol string `toml:"protocol"`
	Zone     *int   `toml:"zone"`

	OrigSrcIP string `toml:"orig_src_ip"`
	SrcIP     string `toml:"src_ip"`
	OrigDstIP string `toml:"orig_dst_ip"`
	DstIP     string `toml:"dst_ip"`

	OrigSrcPort *int `toml:"orig_src_port"`
	SrcPort     *int `toml:"src_port"`
	OrigDstPort *int `toml:"orig_dst_port"`
	DstPort     *int `toml:"dst_port"`

	ReplySrcIP   string `toml:"reply_src_ip"`
	ReplyDstIP   string `toml:"reply_dst_ip"`
	ReplySrcPort *int   `toml:"reply_src_port"`
	ReplyDstPort *int   `toml:"reply_dst_port"`
}

var (
	conntrackDumpOpts   = conntrackDumpOptions{}
	conntrackDeleteOpts = conntrackDeleteOptions{}
)

var conntrackCmd = &cobra.Command{
	Use:   "conntrack",
	Short: "Manage conntrack entries",
	Long: "Manage conntrack entries.\n" +
		"Matcher flags are accepted only after -- separators, or from --matchers-file.",
	Example: "erctl conntrack dump -- --protocol=tcp --orig-dst-port=80\n" +
		"erctl conntrack delete -- --zone=10 --protocol=udp --orig-dst-port=53\n" +
		"erctl conntrack delete --all",
}

var conntrackDumpCmd = &cobra.Command{
	Use:     "dump [-- <matcher-flags>]...",
	Short:   "Dump conntrack entries",
	Long:    conntrackMatcherCommandLong("Dump conntrack entries.", false),
	Example: conntrackMatcherCommandExample("dump"),
	Args:    cobra.ArbitraryArgs,
	RunE: func(_ *cobra.Command, args []string) error {
		matcher, _, err := buildConntrackMatchers(args, conntrackDumpOpts.matchersFile)
		if err != nil {
			return err
		}

		out, err := setOutput()
		if err != nil {
			return err
		}
		return writeConntrackFlows(out, conntrackFamiliesAll(), matcher, conntrackDumpOpts.decode)
	},
}

var conntrackDeleteCmd = &cobra.Command{
	Use:     "delete [--all] [-- <matcher-flags>]...",
	Short:   "Delete conntrack entries",
	Long:    conntrackMatcherCommandLong("Delete conntrack entries.", true),
	Example: conntrackMatcherCommandExample("delete"),
	Args:    cobra.ArbitraryArgs,
	RunE: func(_ *cobra.Command, args []string) error {
		matcher, hasFilter, err := buildConntrackMatchers(args, conntrackDeleteOpts.matchersFile)
		if err != nil {
			return err
		}

		if conntrackDeleteOpts.all {
			if hasFilter {
				return fmt.Errorf("--all cannot be used with filters, -- separators, or --matchers-file")
			}

			if err := netlink.ConntrackTableFlush(netlink.ConntrackTable); err != nil {
				return err
			}
			return nil
		}

		if !hasFilter {
			return fmt.Errorf("at least one filter, matcher after --, or --matchers-file is required")
		}

		_, err = deleteConntrackFlows(conntrackFamiliesAll(), matcher)
		return err
	},
}

var conntrackUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update conntrack entries (not implemented)",
	Long:  "Update conntrack entries (not implemented).",
	Args:  cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		log.Fatal("not implemented")
	},
}

func init() {
	rootCmd.AddCommand(conntrackCmd)

	conntrackCmd.AddCommand(conntrackDumpCmd)
	conntrackCmd.AddCommand(conntrackDeleteCmd)
	conntrackCmd.AddCommand(conntrackUpdateCmd)

	bindConntrackMatchersFileFlag(conntrackDumpCmd, &conntrackDumpOpts.matchersFile)
	conntrackDumpCmd.Flags().BoolVarP(&conntrackDumpOpts.decode, "decode", "D", false, "decode conntrack labels and append decoded fields")

	bindConntrackMatchersFileFlag(conntrackDeleteCmd, &conntrackDeleteOpts.matchersFile)
	conntrackDeleteCmd.Flags().BoolVar(&conntrackDeleteOpts.all, "all", false, "delete all conntrack entries")
}

func defaultConntrackFilterOptions() conntrackFilterOptions {
	return conntrackFilterOptions{
		family:       conntrackFamilyAll,
		zone:         -1,
		origSrcPort:  -1,
		origDstPort:  -1,
		replySrcPort: -1,
		replyDstPort: -1,
	}
}

func bindConntrackMatchersFileFlag(cmd *cobra.Command, matchersFile *string) {
	cmd.Flags().StringVar(matchersFile, "matchers-file", "", "read matchers from a TOML file with [[all.matchers]], [[ipv4.matchers]], or [[ipv6.matchers]]")
}

func bindConntrackMatcherFlags(flagSet *pflag.FlagSet, options *conntrackFilterOptions, includeFamily bool) {
	if includeFamily {
		flagSet.StringVar(&options.family, "family", conntrackFamilyAll, "matcher family: all, ipv4, ipv6")
	}
	flagSet.StringVar(&options.protocol, "protocol", "", "L4 protocol name or number, such as tcp, udp, icmp")
	flagSet.IntVar(&options.zone, "zone", -1, "conntrack zone")
	flagSet.StringVar(&options.origSrcIP, "orig-src-ip", "", "origin tuple source IP")
	flagSet.StringVar(&options.origSrcIP, "src-ip", "", "alias of --orig-src-ip")
	flagSet.StringVar(&options.origDstIP, "orig-dst-ip", "", "origin tuple destination IP")
	flagSet.StringVar(&options.origDstIP, "dst-ip", "", "alias of --orig-dst-ip")
	flagSet.IntVar(&options.origSrcPort, "orig-src-port", -1, "origin tuple source port")
	flagSet.IntVar(&options.origSrcPort, "src-port", -1, "alias of --orig-src-port")
	flagSet.IntVar(&options.origDstPort, "orig-dst-port", -1, "origin tuple destination port")
	flagSet.IntVar(&options.origDstPort, "dst-port", -1, "alias of --orig-dst-port")
	flagSet.StringVar(&options.replySrcIP, "reply-src-ip", "", "reply source IP")
	flagSet.StringVar(&options.replyDstIP, "reply-dst-ip", "", "reply destination IP")
	flagSet.IntVar(&options.replySrcPort, "reply-src-port", -1, "reply source port")
	flagSet.IntVar(&options.replyDstPort, "reply-dst-port", -1, "reply destination port")
}

func conntrackMatcherCommandLong(summary string, includeAll bool) string {
	var b strings.Builder
	b.WriteString(summary)
	b.WriteString("\n\n")
	b.WriteString("Top-level flags:\n")
	b.WriteString("  --matchers-file\n")
	if includeAll {
		b.WriteString("  --all\n")
	}
	b.WriteString("\n")
	b.WriteString("Command-line matcher syntax:\n")
	b.WriteString("  erctl conntrack ")
	if includeAll {
		b.WriteString("delete")
	} else {
		b.WriteString("dump")
	}
	b.WriteString(" -- <matcher-1 flags> [-- <matcher-2 flags> ...]\n\n")
	b.WriteString("Matcher semantics:\n")
	b.WriteString("  - flags within one matcher are ANDed\n")
	b.WriteString("  - multiple matchers are ORed\n\n")
	b.WriteString("Matcher flags (only valid after --, or in --matchers-file):\n")
	b.WriteString("  --family\n")
	b.WriteString("  --zone\n")
	b.WriteString("  --protocol\n")
	b.WriteString("  --orig-src-ip, --src-ip\n")
	b.WriteString("  --orig-dst-ip, --dst-ip\n")
	b.WriteString("  --orig-src-port, --src-port\n")
	b.WriteString("  --orig-dst-port, --dst-port\n")
	b.WriteString("  --reply-src-ip\n")
	b.WriteString("  --reply-dst-ip\n")
	b.WriteString("  --reply-src-port\n")
	b.WriteString("  --reply-dst-port\n")
	if includeAll {
		b.WriteString("\n")
		b.WriteString("--all cannot be combined with matchers or --matchers-file.\n")
	}
	return b.String()
}

func conntrackMatcherCommandExample(subcommand string) string {
	return fmt.Sprintf("erctl conntrack %s -- --protocol=tcp --orig-dst-port=80\n"+
		"erctl conntrack %s -- --zone=10 --protocol=tcp --orig-dst-port=80 -- --family=ipv6 --zone=10 --protocol=udp --orig-dst-port=53\n"+
		"erctl conntrack %s --matchers-file /path/to/conntrack-matchers.toml", subcommand, subcommand, subcommand)
}

func parseConntrackMatcherFamily(value string) (uint8, bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", conntrackFamilyAll:
		return 0, false, nil
	case "4", "v4", conntrackFamilyIPv4:
		return unix.AF_INET, true, nil
	case "6", "v6", conntrackFamilyIPv6:
		return unix.AF_INET6, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported conntrack family %q", value)
	}
}

func parseConntrackProtocol(value string) (uint8, bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return 0, false, nil
	case "tcp":
		return 6, true, nil
	case "udp":
		return 17, true, nil
	case "icmp":
		return 1, true, nil
	case "icmpv6":
		return 58, true, nil
	case "sctp":
		return 132, true, nil
	}

	protocol, err := strconv.ParseUint(value, 10, 8)
	if err != nil || protocol == 0 {
		return 0, false, fmt.Errorf("unsupported conntrack protocol %q", value)
	}
	return uint8(protocol), true, nil
}

func parseConntrackUint16Flag(name string, value int) (uint16, bool, error) {
	if value < 0 {
		return 0, false, nil
	}
	if value > conntrackMaxUint16 {
		return 0, false, fmt.Errorf("%s must be in range [0, %d]", name, conntrackMaxUint16)
	}
	return uint16(value), true, nil
}

func buildConntrackFilter(options conntrackFilterOptions, includeFamily bool, includeZone bool) (ctmgr.Matcher, bool, error) {
	filter := &conntrackMatcher{}
	hasFilter := false

	if includeFamily {
		hasFamily, err := applyConntrackFamilyFilter(filter, options.family)
		if err != nil {
			return nil, false, err
		}
		hasFilter = hasFilter || hasFamily
	}

	hasProtocol, err := applyConntrackProtocolFilter(filter, options.protocol)
	if err != nil {
		return nil, false, err
	}
	hasFilter = hasFilter || hasProtocol

	if includeZone {
		hasZone, err := applyConntrackZoneFilter(filter, options.zone)
		if err != nil {
			return nil, false, err
		}
		hasFilter = hasFilter || hasZone
	}

	hasIPFilter, err := applyConntrackIPFilters(filter, options)
	if err != nil {
		return nil, false, err
	}
	hasFilter = hasFilter || hasIPFilter

	hasPortFilter, err := applyConntrackPortFilters(filter, options)
	if err != nil {
		return nil, false, err
	}
	hasFilter = hasFilter || hasPortFilter

	if !hasFilter {
		return nil, false, nil
	}
	return filter, true, nil
}

func applyConntrackFamilyFilter(filter *conntrackMatcher, familyValue string) (bool, error) {
	family, hasFamily, err := parseConntrackMatcherFamily(familyValue)
	if err != nil {
		return false, err
	}
	if hasFamily {
		filter.flowMatcher.IPFamily = family
	}
	return hasFamily, nil
}

func applyConntrackProtocolFilter(filter *conntrackMatcher, protocolValue string) (bool, error) {
	protocol, hasProtocol, err := parseConntrackProtocol(protocolValue)
	if err != nil {
		return false, err
	}
	if hasProtocol {
		filter.flowMatcher.IPProtocol = protocol
	}
	return hasProtocol, nil
}

func applyConntrackZoneFilter(filter *conntrackMatcher, zoneValue int) (bool, error) {
	zone, hasZone, err := parseConntrackUint16Flag("--zone", zoneValue)
	if err != nil {
		return false, err
	}
	if hasZone {
		filter.zone = &zone
	}
	return hasZone, nil
}

func applyConntrackIPFilter(value, flagName string, targetIP *[16]byte, targetLen *int) (bool, error) {
	if value == "" {
		return false, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false, fmt.Errorf("invalid %s %q", flagName, value)
	}
	*targetIP = ipTo16(ip)
	*targetLen = 128
	return true, nil
}

func applyConntrackIPFilters(filter *conntrackMatcher, options conntrackFilterOptions) (bool, error) {
	hasFilter := false
	for _, ipField := range []struct {
		value     string
		flagName  string
		targetIP  *[16]byte
		targetLen *int
	}{
		{options.origSrcIP, "--orig-src-ip", &filter.flowMatcher.Src.SrcIP, &filter.flowMatcher.Src.SrcIPPrefixLen},
		{options.origDstIP, "--orig-dst-ip", &filter.flowMatcher.Src.DstIP, &filter.flowMatcher.Src.DstIPPrefixLen},
		{options.replySrcIP, "--reply-src-ip", &filter.flowMatcher.Dst.SrcIP, &filter.flowMatcher.Dst.SrcIPPrefixLen},
		{options.replyDstIP, "--reply-dst-ip", &filter.flowMatcher.Dst.DstIP, &filter.flowMatcher.Dst.DstIPPrefixLen},
	} {
		applied, err := applyConntrackIPFilter(ipField.value, ipField.flagName, ipField.targetIP, ipField.targetLen)
		if err != nil {
			return false, err
		}
		hasFilter = hasFilter || applied
	}
	return hasFilter, nil
}

func applyConntrackPortFilter(value int, flagName string, target *uint16) (bool, error) {
	port, hasPort, err := parseConntrackUint16Flag(flagName, value)
	if err != nil {
		return false, err
	}
	if hasPort {
		*target = port
	}
	return hasPort, nil
}

func applyConntrackPortFilters(filter *conntrackMatcher, options conntrackFilterOptions) (bool, error) {
	hasFilter := false
	for _, portField := range []struct {
		value    int
		flagName string
		target   *uint16
	}{
		{options.origSrcPort, "--orig-src-port", &filter.flowMatcher.Src.SrcPort},
		{options.origDstPort, "--orig-dst-port", &filter.flowMatcher.Src.DstPort},
		{options.replySrcPort, "--reply-src-port", &filter.flowMatcher.Dst.SrcPort},
		{options.replyDstPort, "--reply-dst-port", &filter.flowMatcher.Dst.DstPort},
	} {
		applied, err := applyConntrackPortFilter(portField.value, portField.flagName, portField.target)
		if err != nil {
			return false, err
		}
		hasFilter = hasFilter || applied
	}
	return hasFilter, nil
}

func buildConntrackMatchers(args []string, matchersFile string) (ctmgr.Matcher, bool, error) {
	matchers := make([]ctmgr.Matcher, 0, 4)
	extraMatchers, err := parseConntrackMatchersFromArgs(args)
	if err != nil {
		return nil, false, err
	}
	matchers = append(matchers, extraMatchers...)

	fileMatchers, err := loadConntrackMatchersFromTOMLFile(matchersFile)
	if err != nil {
		return nil, false, err
	}
	matchers = append(matchers, fileMatchers...)

	return mergeConntrackMatchers(matchers)
}

func parseConntrackMatchersFromArgs(args []string) ([]ctmgr.Matcher, error) {
	if len(args) == 0 {
		return nil, nil
	}

	groups := splitConntrackMatcherArgs(args)
	matchers := make([]ctmgr.Matcher, 0, len(groups))
	for i := range groups {
		if len(groups[i]) == 0 {
			return nil, fmt.Errorf("empty matcher around -- separator")
		}

		options := defaultConntrackFilterOptions()
		flagSet := pflag.NewFlagSet(fmt.Sprintf("conntrack-matcher-%d", i+1), pflag.ContinueOnError)
		flagSet.SetOutput(io.Discard)
		bindConntrackMatcherFlags(flagSet, &options, true)
		if err := flagSet.Parse(groups[i]); err != nil {
			return nil, fmt.Errorf("parse matcher %d after --: %w", i+1, err)
		}
		if len(flagSet.Args()) != 0 {
			return nil, fmt.Errorf("unexpected positional args in matcher %d: %v", i+1, flagSet.Args())
		}

		matcher, hasFilter, err := buildConntrackFilter(options, true, true)
		if err != nil {
			return nil, fmt.Errorf("build matcher %d after --: %w", i+1, err)
		}
		if !hasFilter {
			return nil, fmt.Errorf("matcher %d after -- is empty", i+1)
		}
		matchers = append(matchers, matcher)
	}
	return matchers, nil
}

func splitConntrackMatcherArgs(args []string) [][]string {
	groups := make([][]string, 0, 1)
	current := make([]string, 0, len(args))
	for i := range args {
		if args[i] == "--" {
			groups = append(groups, current)
			current = nil
			continue
		}
		current = append(current, args[i])
	}
	groups = append(groups, current)
	return groups
}

func loadConntrackMatchersFromTOMLFile(matchersFile string) ([]ctmgr.Matcher, error) {
	if matchersFile == "" {
		return nil, nil
	}

	var config conntrackRuleFile
	md, err := toml.DecodeFile(matchersFile, &config)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("unknown keys in matchers file %q: %v", matchersFile, undecoded)
	}
	if len(config.All.Matchers) == 0 && len(config.IPv4.Matchers) == 0 && len(config.IPv6.Matchers) == 0 {
		return nil, fmt.Errorf("matchers file %q does not contain any [[all.matchers]], [[ipv4.matchers]], or [[ipv6.matchers]]", matchersFile)
	}

	matchers := make([]ctmgr.Matcher, 0, len(config.All.Matchers)+len(config.IPv4.Matchers)+len(config.IPv6.Matchers))
	appendMatchers := func(defaultFamily string, items []conntrackRuleFileMatcher, baseIndex int) error {
		for i := range items {
			options, err := items[i].toFilterOptions(defaultFamily)
			if err != nil {
				return fmt.Errorf("matchers file %q matcher %d: %w", matchersFile, baseIndex+i+1, err)
			}
			matcher, hasFilter, err := buildConntrackFilter(options, true, true)
			if err != nil {
				return fmt.Errorf("matchers file %q matcher %d: %w", matchersFile, baseIndex+i+1, err)
			}
			if !hasFilter {
				return fmt.Errorf("matchers file %q matcher %d is empty", matchersFile, baseIndex+i+1)
			}
			matchers = append(matchers, matcher)
		}
		return nil
	}
	base := 0
	if err := appendMatchers(conntrackFamilyAll, config.All.Matchers, base); err != nil {
		return nil, err
	}
	base += len(config.All.Matchers)
	if err := appendMatchers(conntrackFamilyIPv4, config.IPv4.Matchers, base); err != nil {
		return nil, err
	}
	base += len(config.IPv4.Matchers)
	if err := appendMatchers(conntrackFamilyIPv6, config.IPv6.Matchers, base); err != nil {
		return nil, err
	}
	return matchers, nil
}

func (m conntrackRuleFileMatcher) toFilterOptions(defaultFamily string) (conntrackFilterOptions, error) {
	options := defaultConntrackFilterOptions()
	options.family = defaultFamily
	var err error
	options.protocol = strings.TrimSpace(m.Protocol)

	if m.Zone != nil {
		options.zone = *m.Zone
	}

	options.origSrcIP, err = chooseStringValue("orig_src_ip", m.OrigSrcIP, "src_ip", m.SrcIP)
	if err != nil {
		return options, err
	}
	options.origDstIP, err = chooseStringValue("orig_dst_ip", m.OrigDstIP, "dst_ip", m.DstIP)
	if err != nil {
		return options, err
	}
	options.origSrcPort, err = chooseIntValue("orig_src_port", m.OrigSrcPort, "src_port", m.SrcPort, -1)
	if err != nil {
		return options, err
	}
	options.origDstPort, err = chooseIntValue("orig_dst_port", m.OrigDstPort, "dst_port", m.DstPort, -1)
	if err != nil {
		return options, err
	}

	options.replySrcIP = strings.TrimSpace(m.ReplySrcIP)
	options.replyDstIP = strings.TrimSpace(m.ReplyDstIP)
	options.replySrcPort = derefIntOr(m.ReplySrcPort, -1)
	options.replyDstPort = derefIntOr(m.ReplyDstPort, -1)

	return options, nil
}

func chooseStringValue(canonicalName, canonicalValue, aliasName, aliasValue string) (string, error) {
	canonicalValue = strings.TrimSpace(canonicalValue)
	aliasValue = strings.TrimSpace(aliasValue)
	switch {
	case canonicalValue == "":
		return aliasValue, nil
	case aliasValue == "":
		return canonicalValue, nil
	case canonicalValue == aliasValue:
		return canonicalValue, nil
	default:
		return "", fmt.Errorf("%s conflicts with %s", canonicalName, aliasName)
	}
}

func chooseIntValue(canonicalName string, canonicalValue *int, aliasName string, aliasValue *int, defaultValue int) (int, error) {
	switch {
	case canonicalValue == nil && aliasValue == nil:
		return defaultValue, nil
	case canonicalValue == nil:
		return *aliasValue, nil
	case aliasValue == nil:
		return *canonicalValue, nil
	case *canonicalValue == *aliasValue:
		return *canonicalValue, nil
	default:
		return defaultValue, fmt.Errorf("%s conflicts with %s", canonicalName, aliasName)
	}
}

func derefIntOr(value *int, defaultValue int) int {
	if value == nil {
		return defaultValue
	}
	return *value
}

func mergeConntrackMatchers(matchers []ctmgr.Matcher) (ctmgr.Matcher, bool, error) {
	switch len(matchers) {
	case 0:
		return nil, false, nil
	case 1:
		return matchers[0], true, nil
	default:
		return &conntrackMultiMatcher{matchers: matchers}, true, nil
	}
}

func writeConntrackFlows(out io.Writer, families []uint8, matcher ctmgr.Matcher, decode bool) error {
	conntrackFlowAllocator, conntrackFlowDeallocator := newConntrackFlowPool()
	for i := range families {
		_, _, err := ctmgr.DumpConntrackFlows(
			families[i],
			matcher,
			conntrackFlowAllocator,
			conntrackFlowDeallocator,
			func(flow *netlink.ConntrackFlow) error {
				_, err := fmt.Fprintln(out, formatConntrackFlowOVS(flow, decode))
				return err
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteConntrackFlows(families []uint8, matcher ctmgr.Matcher) (uint, error) {
	conntrackFlowAllocator, conntrackFlowDeallocator := newConntrackFlowPool()
	var deleted uint
	for i := range families {
		_, _, successCount, _, err := ctmgr.DeleteConntrackFlows(
			families[i],
			matcher,
			conntrackFlowAllocator,
			conntrackFlowDeallocator,
		)
		deleted += uint(successCount)
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

func newConntrackFlowPool() (func() *netlink.ConntrackFlow, func(*netlink.ConntrackFlow)) {
	pool := sync.Pool{
		New: func() any {
			return &netlink.ConntrackFlow{}
		},
	}
	return func() *netlink.ConntrackFlow {
			return pool.Get().(*netlink.ConntrackFlow)
		}, func(flow *netlink.ConntrackFlow) {
			pool.Put(flow)
		}
}

func conntrackFamiliesAll() []uint8 {
	return []uint8{unix.AF_INET, unix.AF_INET6}
}

func ipTo16(ip net.IP) [16]byte {
	var out [16]byte
	if v4 := ip.To4(); v4 != nil {
		out[10] = 0xff
		out[11] = 0xff
		copy(out[12:], v4)
		return out
	}
	copy(out[:], ip.To16())
	return out
}

func formatConntrackFlowOVS(flow *netlink.ConntrackFlow, decode bool) string {
	var b strings.Builder
	b.WriteString(protocolName(flow.Forward.Protocol))
	b.WriteString(",orig=(")
	b.WriteString(formatConntrackTupleOVS(&flow.Forward))
	b.WriteString("),reply=(")
	b.WriteString(formatConntrackTupleOVS(&flow.Reverse))

	b.WriteString(")")
	if flow.TimeStart != 0 {
		b.WriteString(",start=")
		b.WriteString(formatConntrackTimestamp(flow.TimeStart))
	}
	if flow.TimeStop != 0 {
		b.WriteString(",stop=")
		b.WriteString(formatConntrackTimestamp(flow.TimeStop))
	}
	if flow.ID != 0 {
		b.WriteString(",id=")
		b.WriteString(strconv.FormatUint(uint64(flow.ID), 10))
	}
	b.WriteString(",zone=")
	b.WriteString(strconv.FormatUint(uint64(flow.Zone), 10))
	if flow.HasStatus || flow.Status != 0 {
		b.WriteString(",status=")
		b.WriteString(formatConntrackStatus(flow.Status))
	}
	if flow.HasTimeout || flow.TimeOut != 0 {
		b.WriteString(",timeout=")
		b.WriteString(strconv.FormatUint(uint64(flow.TimeOut), 10))
	}
	if flow.HasMark || flow.Mark != 0 {
		b.WriteString(",mark=")
		b.WriteString(strconv.FormatUint(uint64(flow.Mark), 10))
	}
	if flow.HasLabels {
		b.WriteString(",labels=0x")
		b.WriteString(formatConntrackLabelHex(flow.Labels))
		if flow.HasLabelsMask {
			b.WriteString("/0x")
			b.WriteString(formatConntrackLabelHex(flow.LabelsMask))
		}
	}
	if flow.Use != 0 {
		b.WriteString(",use=")
		b.WriteString(strconv.FormatUint(uint64(flow.Use), 10))
	}
	if decode {
		appendDecodedCTLabelFields(&b, flow)
	}

	return b.String()
}

func appendDecodedCTLabelFields(b *strings.Builder, flow *netlink.ConntrackFlow) {
	if !flow.HasLabels {
		return
	}

	_, info, err := decodeConntrackLabel(flow.Labels[:])
	if err != nil {
		b.WriteString(",label_decode_error=")
		b.WriteString(err.Error())
		return
	}

	for _, field := range collectFormattedInfoFields(info) {
		if field.Key == "" {
			continue
		}
		b.WriteString(",label_")
		b.WriteString(field.Key)
		b.WriteString("=")
		b.WriteString(field.Value)
	}
}

func formatConntrackLabelHex(label [16]byte) string {
	value := numeric.Uint128FromLittleEndianBytes(label[:])
	return fmt.Sprintf("%016x%016x", value.High, value.Low)
}

func formatConntrackTupleOVS(tuple *netlink.IPTuple) string {
	var b strings.Builder
	b.WriteString("src=")
	b.WriteString(tuple.SrcIP.String())
	b.WriteString(",dst=")
	b.WriteString(tuple.DstIP.String())
	b.WriteString(",proto=")
	b.WriteString(protocolName(tuple.Protocol))

	switch tuple.Protocol {
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		b.WriteString(",id=")
		b.WriteString(strconv.FormatUint(uint64(tuple.ICMPID), 10))
		b.WriteString(",type=")
		b.WriteString(strconv.FormatUint(uint64(tuple.ICMPType), 10))
		b.WriteString(",code=")
		b.WriteString(strconv.FormatUint(uint64(tuple.ICMPCode), 10))
	default:
		b.WriteString(",sport=")
		b.WriteString(strconv.FormatUint(uint64(tuple.SrcPort), 10))
		b.WriteString(",dport=")
		b.WriteString(strconv.FormatUint(uint64(tuple.DstPort), 10))
	}

	b.WriteString(",packets=")
	b.WriteString(strconv.FormatUint(tuple.Packets, 10))
	b.WriteString(",bytes=")
	b.WriteString(strconv.FormatUint(tuple.Bytes, 10))
	return b.String()
}

func formatConntrackTimestamp(nsec uint64) string {
	return time.Unix(0, int64(nsec)).UTC().Format("2006-01-02T15:04:05.000000000Z")
}

type conntrackStatusFlag struct {
	mask uint32
	name string
}

var conntrackStatusFlags = []conntrackStatusFlag{
	{mask: 1 << 0, name: "EXPECTED"},
	{mask: 1 << 1, name: "SEEN_REPLY"},
	{mask: 1 << 2, name: "ASSURED"},
	{mask: 1 << 3, name: "CONFIRMED"},
	{mask: 1 << 4, name: "SRC_NAT"},
	{mask: 1 << 5, name: "DST_NAT"},
	{mask: 1 << 6, name: "SEQ_ADJUST"},
	{mask: 1 << 7, name: "SRC_NAT_DONE"},
	{mask: 1 << 8, name: "DST_NAT_DONE"},
	{mask: 1 << 9, name: "DYING"},
	{mask: 1 << 10, name: "FIXED_TIMEOUT"},
	{mask: 1 << 11, name: "TEMPLATE"},
}

func formatConntrackStatus(status uint32) string {
	if status == 0 {
		return "0x0"
	}

	parts := make([]string, 0, len(conntrackStatusFlags))
	remaining := status
	for i := range conntrackStatusFlags {
		if status&conntrackStatusFlags[i].mask == 0 {
			continue
		}
		parts = append(parts, conntrackStatusFlags[i].name)
		remaining &^= conntrackStatusFlags[i].mask
	}

	if remaining != 0 || len(parts) == 0 {
		parts = append(parts, "0x"+strconv.FormatUint(uint64(remaining), 16))
	}

	return strings.Join(parts, "|")
}

func protocolName(proto uint8) string {
	switch proto {
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_ICMPV6:
		return "icmpv6"
	case unix.IPPROTO_SCTP:
		return "sctp"
	case unix.IPPROTO_UDPLITE:
		return "udplite"
	case unix.IPPROTO_DCCP:
		return "dccp"
	case unix.IPPROTO_IGMP:
		return "igmp"
	case unix.IPPROTO_IPIP:
		return "ip"
	case unix.IPPROTO_IPV6:
		return "ipv6"
	case unix.IPPROTO_GRE:
		return "gre"
	default:
		return strconv.FormatUint(uint64(proto), 10)
	}
}
