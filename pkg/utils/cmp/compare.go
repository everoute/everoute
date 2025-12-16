package cmp

func MaxTotalOrdered[T BuiltinTotalOrdered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func MinTotalOrdered[T BuiltinTotalOrdered](a, b T) T {
	if a < b {
		return a
	}
	return b
}
