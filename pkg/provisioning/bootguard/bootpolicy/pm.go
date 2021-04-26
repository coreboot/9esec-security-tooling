package bootpolicy

type PM struct {
	StructInfo `id:"__PMDA__" version:"0x20"`

	Data []byte `json:"pcData"`
}
