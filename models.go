package main

type targetProc struct {
	pidInt  int32
	exeName string
	cmdLine string
}

type resultStrings struct {
	memRegion   int32
	memSize     int32
	index       int
	str         string
	startOffset int
	endOffset   int
}
