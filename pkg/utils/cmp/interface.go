package cmp

type BuiltinTotalOrdered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~string
}

type BuiltinPartialOrdered interface {
	~float32 | ~float64
}

type BuiltinOrdered interface {
	BuiltinTotalOrdered | BuiltinPartialOrdered
}
