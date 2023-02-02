package ffs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"text/tabwriter"

	fianoGUID "github.com/linuxboot/fiano/pkg/guid"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
	"github.com/xaionaro-go/unsafetools"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

// NameToRangesMap returns a map which maps node ID ("nameString") to its Range.
//
// If the node has GUID then "ID" is the GUID. If not, then
// the node is identified by its type in format ("node/"+typeName).
//
// Since multiple nodes may have the same GUID (and especially the same type),
// we enumerate nodes with the same "ID".
func (node *Node) NameToRangesMap() map[string]pkgbytes.Ranges {
	// Unfortunately fiano does not support any way to extract offset at the moment, so we use this hacky
	// way to do that.
	//
	// See also: https://github.com/linuxboot/fiano/issues/164
	rangeMap := map[string]pkgbytes.Ranges{}
	table := visitors.Table{
		W: &tabwriter.Writer{},
	}
	*unsafetools.FieldByName(&table, `printRow`).(*func(v *visitors.Table, node, name, typez interface{}, offset, length uint64)) =
		func(v *visitors.Table, _node, name, typez interface{}, offset, length uint64) {
			nameString, _ := name.(string)
			if nameString == `` {
				nameString = "node/" + fmt.Sprint(_node) // for BIOSRegion results into "node/BIOS"
			}
			if nameString == `` {
				return
			}
			adjustedOffset := int64(offset) + node.AddOffset
			if adjustedOffset < 0 {
				// TODO: add support of negative offsets (currently we do not support them, because we use an unsigned integer for an offset)
				return
			}
			rangeMap[nameString] = append(rangeMap[nameString], pkgbytes.Range{
				Offset: uint64(adjustedOffset),
				Length: length,
			})
		}
	_ = table.Run(node.Firmware) // TODO: handle the error here somehow
	return rangeMap
}

type NodeVisitor struct {
	Callback                 func(node Node) (bool, error)
	FallbackToContainerRange bool

	isSkipping bool

	// isProcessedSection means we are currently scanning
	// a processed area (so absolute offsets has no sense in here)
	isProcessedSection bool
	containerRange     *pkgbytes.Range

	rangeMap map[string]pkgbytes.Ranges
	countMap map[string]uint
}

func (v *NodeVisitor) Run(f fianoUEFI.Firmware) error {
	v.countMap = map[string]uint{}
	node, ok := f.(*Node)
	if !ok {
		node = &Node{Firmware: f}
	}
	v.rangeMap = node.NameToRangesMap()
	return node.Apply(v)
}

func (v *NodeVisitor) Visit(f fianoUEFI.Firmware) error {

	/* Gathering additional information */

	firmwareRange := pkgbytes.Range{
		Offset: uint64(math.MaxUint64),
		Length: uint64(len(f.Buf())),
	}

	if v.FallbackToContainerRange && v.containerRange != nil {
		firmwareRange = *v.containerRange
	}

	// Gathering additional information: getting "name".
	//
	// We use guid.String() as the name if it is available.
	// In the "GALAGOPRO3" image there's a FirmwareVolume with
	// zero-valued GUID. And it is not added to `v.rangeMap` by
	// `NameToRangesMap`, so we have to ignore zero-valued GUID as well
	var name string

	guid := Node{Firmware: f}.GUID()
	var emptyGUID fianoGUID.GUID
	if guid != nil && !bytes.Equal(guid[:], emptyGUID[:]) {
		name = guid.String()
	} else {
		switch f.(type) {
		case *fianoUEFI.BIOSRegion:
			// See `NameToRangesMap`. This name is manually set in line:
			//     nameString = "node/" + fmt.Sprint(node)
			name = "node/BIOS"
		}
	}

	// Gathering additional information: getting the offset
	//
	// Since we extract it from "rangeMap" we need a non-empty name for that.
	if name != `` {
		// See also description of `NameToRangesMap`.
		//
		// Since multiple nodes may have the same name ("ID"), we
		// extract nodes in the same order how they we appended to
		// `v.rangeMap[name]`.
		//
		// It works because both `volumeVisitor` and `visitors.Table`
		// traverses the FFS in the same order.
		count := v.countMap[name]
		if !v.isProcessedSection {
			firmwareRange.Offset = v.rangeMap[name][count].Offset
		}
		v.countMap[name]++
	}

	/* Calling the Callback */

	if !v.isSkipping {
		shouldContinue, err := v.Callback(Node{
			Firmware: f,
			Range:    firmwareRange,
		})
		if err != nil {
			return err
		}
		if !shouldContinue {
			v.isSkipping = true
			defer func() {
				v.isSkipping = false
			}()
		}
	}

	/* Continuing the traversal */

	if f, ok := f.(*fianoUEFI.Section); ok {
		// If the section is decompressed, then absolute offsets
		// does not make any sense, and therefore we need to
		// do not report the offsets in such areas.
		//
		// So we are checking if the section is processed/decompressed:
		if f.Header.Type == fianoUEFI.SectionTypeGUIDDefined {
			var hdr fianoUEFI.SectionGUIDDefinedHeader
			if err := binary.Read(bytes.NewReader(f.Buf()), binaryOrder, &hdr); err != nil {
				return fmt.Errorf("unable to read the SectionGUIDDefinedHeader: %w", err)
			}
			if hdr.Attributes&uint16(fianoUEFI.GUIDEDSectionProcessingRequired) != 0 {
				// The area was processed (most likely decompressed), and absolute
				// offsets does not work here. Setting "isProcessedSection"
				// for children:
				if !v.isProcessedSection {
					v.containerRange = &firmwareRange
					v.isProcessedSection = true
					defer func() {
						v.isProcessedSection = false
						v.containerRange = nil
					}()
				}
				return f.ApplyChildren(v)
			}
		}
	}

	return f.ApplyChildren(v)
}
