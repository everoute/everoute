package types

type NicDirect int

// for print log
func (n NicDirect) String() string {
	if n == NicIn {
		return "in"
	}
	if n == NicOut {
		return "out"
	}
	return ""
}

const (
	NicIn  NicDirect = 1
	NicOut NicDirect = 2
)
