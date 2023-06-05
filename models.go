package main

type targetProc struct {
	pidInt  int32
	exeName string
	cmdLine string
}

type resultStrings struct {
	memRegion   uint64
	memSize     int32
	index       int
	str         string
	startOffset int
	endOffset   int
}
