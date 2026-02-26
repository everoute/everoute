/*
Package conntrack provides policy matcher matching against Linux conntrack flows.

It defines Matcher for single-matcher matching and MatcherBatch for efficient batch matching.
Matchers are organized by IP prefix (exact match map, binary trie for subnets, and any-IP
matchers) and by protocol (TCP, UDP, ICMP, other) to reduce comparisons. Flows are matched
against the policy zone range; IPv4 flows are normalized to IPv4-mapped format for unified
handling.
*/
package conntrack
