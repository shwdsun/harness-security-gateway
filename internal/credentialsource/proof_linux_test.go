//go:build linux

package credentialsource

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func syntheticIdentity() kernelIdentity {
	uuid, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	return kernelIdentity{uuid, [3]fileHandle{
		{1, []byte{1, 0, 0, 0, 2, 0, 0, 0}},
		{1, []byte{2, 0, 0, 0, 2, 0, 0, 0}},
		{1, []byte{3, 0, 0, 0, 2, 0, 0, 0}},
	}}
}

func syntheticReader([3]*os.File, [3]objectID) (kernelIdentity, error) {
	return syntheticIdentity(), nil
}

func TestProofFrozenEncodingVectors(t *testing.T) {
	id := syntheticIdentity()
	digest, err := objectDigest(id.uuid, id.handles[0])
	must(t, err)
	if digest != "f6e232218556022c5847877cd416ba6bce40fc7b570ebaf1e6752f4d8e658897" {
		t.Fatal("object encoding changed")
	}
	locator, err := locatorDigest("/srv/hsg/credentials", "slot-one")
	must(t, err)
	if locator != "af323ee479712026f4bc77da21261a122bffb4e9e2cd4eae00a984c5f7003978" {
		t.Fatal("locator encoding changed")
	}
	// Ambiguous concatenation must not create equal locator encodings.
	a, err := locatorDigest("/srv/a", "bc")
	must(t, err)
	b, err := locatorDigest("/srv/ab", "c")
	must(t, err)
	if a == b {
		t.Fatal("locator fields are not framed")
	}
	_, err = locatorDigest("/srv/凭据", "slot-one")
	must(t, err)
}

func TestProofRejectsUnsupportedIdentityAndLocator(t *testing.T) {
	cases := map[string]func(*kernelIdentity){
		"missing uuid":   func(id *kernelIdentity) { id.uuid = nil },
		"short uuid":     func(id *kernelIdentity) { id.uuid = id.uuid[:15] },
		"long uuid":      func(id *kernelIdentity) { id.uuid = append(id.uuid, 0) },
		"zero uuid":      func(id *kernelIdentity) { id.uuid = make([]byte, 16) },
		"negative type":  func(id *kernelIdentity) { id.handles[0].kind = -1 },
		"zero type":      func(id *kernelIdentity) { id.handles[0].kind = 0 },
		"other type":     func(id *kernelIdentity) { id.handles[0].kind = 2 },
		"invalid type":   func(id *kernelIdentity) { id.handles[0].kind = 255 },
		"missing handle": func(id *kernelIdentity) { id.handles[0].data = nil },
		"short handle":   func(id *kernelIdentity) { id.handles[0].data = id.handles[0].data[:7] },
		"long handle":    func(id *kernelIdentity) { id.handles[0].data = append(id.handles[0].data, 0) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			id := syntheticIdentity()
			change(&id)
			if digest, err := objectDigest(id.uuid, id.handles[0]); digest != "" || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsupported native identity produced a digest")
			}
		})
	}
	for _, root := range []string{"", "/", "relative", "/srv/../srv", "/srv/", "/srv//credentials", "/srv/\x00", "/srv/\xff", "/srv/\n", "/" + strings.Repeat("a", 4096)} {
		if digest, err := locatorDigest(root, "slot-one"); digest != "" || !errors.Is(err, ErrUnsafe) {
			t.Fatal("unsafe locator produced a digest")
		}
	}
	for _, directory := range []string{"", ".hidden", "..", "a/b", "/slot", "auth.json", "A", "凭据", "bad\x00", strings.Repeat("a", 129)} {
		if digest, err := locatorDigest("/srv/credentials", directory); digest != "" || !errors.Is(err, ErrUnsafe) {
			t.Fatal("unsafe directory produced a digest")
		}
	}
}

func TestProofShapeRejectsMissingAndUnknownFields(t *testing.T) {
	good := Proof{EnrollmentScheme, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	must(t, good.Validate())
	if !errors.Is((Proof{}).Validate(), ErrInvalidProof) {
		t.Fatal("zero proof accepted")
	}
	for _, scheme := range []string{"", "linux-ext4-source/v2", " linux-ext4-source/v1"} {
		p := good
		p.Scheme = scheme
		if !errors.Is(p.Validate(), ErrInvalidProof) {
			t.Fatal("unknown scheme accepted")
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), "sha256:" + strings.Repeat("a", 64)} {
		for field := range 3 {
			p := good
			*[]*string{&p.RootObjectDigest, &p.SlotObjectDigest, &p.LocatorDigest}[field] = bad
			if !errors.Is(p.Validate(), ErrInvalidProof) {
				t.Fatal("malformed digest accepted")
			}
		}
	}
}

func TestProofObservationAndInPlaceUpdate(t *testing.T) {
	f := newFixture(t)
	h := holdFixture(t, f)
	source, proof, err := h.observeProof(syntheticReader, nil)
	must(t, err)
	must(t, proof.Validate())
	must(t, os.WriteFile(f.auth, []byte("synthetic-refresh-changed-bytes"), 0o600))
	next, again, err := h.observeProof(syntheticReader, &proofExpectation{source, proof})
	must(t, err)
	if next != source || again != proof {
		t.Fatal("in-place update changed proof")
	}
	offset, err := h.file.Seek(0, io.SeekCurrent)
	must(t, err)
	if offset != 0 {
		t.Fatal("observation consumed credential content")
	}
}

func TestProofMismatchChecksEveryPinAndRetainsLocks(t *testing.T) {
	for _, field := range []string{"source", "root", "slot", "locator"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			h := holdFixture(t, f)
			source, proof, err := h.observeProof(syntheticReader, nil)
			must(t, err)
			expected := proofExpectation{source, proof}
			switch field {
			case "source":
				expected.sourceDigest = strings.Repeat("f", 64)
			case "root":
				expected.proof.RootObjectDigest = strings.Repeat("f", 64)
			case "slot":
				expected.proof.SlotObjectDigest = strings.Repeat("f", 64)
			case "locator":
				expected.proof.LocatorDigest = strings.Repeat("f", 64)
			}
			got, partial, err := h.observeProof(syntheticReader, &expected)
			if got != "" || partial != (Proof{}) || !errors.Is(err, ErrProofMismatch) {
				t.Fatal("mismatched proof accepted or partial proof returned")
			}
			if _, _, err := h.observeProof(syntheticReader, &proofExpectation{source, proof}); !errors.Is(err, ErrChanged) {
				t.Fatal("corrected expected value revived invalid handle")
			}
			if next, err := Hold(f.root, "slot-one"); next != nil || !errors.Is(err, ErrBusy) {
				t.Fatal("proof mismatch released the slot lock")
			}
			must(t, h.Close())
			holdFixture(t, f)
		})
	}
}

func TestMalformedExpectedProofDoesNotQuerySource(t *testing.T) {
	f := newFixture(t)
	h := holdFixture(t, f)
	source, proof, err := h.observeProof(syntheticReader, nil)
	must(t, err)
	reader := func([3]*os.File, [3]objectID) (kernelIdentity, error) {
		t.Fatal("malformed expectation reached the kernel reader")
		return kernelIdentity{}, nil
	}
	for _, expected := range []proofExpectation{{"", proof}, {strings.ToUpper(source), proof}, {source, Proof{}}} {
		if _, _, err := h.observeProof(reader, &expected); !errors.Is(err, ErrInvalidProof) {
			t.Fatal("malformed expectation accepted")
		}
	}
	if err := h.VerifyProof("", Proof{}); !errors.Is(err, ErrInvalidProof) {
		t.Fatal("public comparator accepted missing proof")
	}
	must(t, h.Validate()) // No source observation failed; input was rejected first.
}

func TestProofCollectionFailureAndReplacement(t *testing.T) {
	for _, kind := range []string{"query failure", "invalid uuid", "invalid slot handle", "replace before", "replace during"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			h := holdFixture(t, f)
			replace := func() {
				must(t, os.Rename(f.auth, filepath.Join(f.parent, "old")))
				writeSynthetic(t, f.auth)
			}
			if kind == "replace before" {
				replace()
			}
			reader := func([3]*os.File, [3]objectID) (kernelIdentity, error) {
				id := syntheticIdentity()
				switch kind {
				case "query failure":
					return kernelIdentity{}, errors.New("untrusted error /secret/source synthetic-token")
				case "invalid uuid":
					id.uuid = nil
				case "invalid slot handle":
					id.handles[1].kind = 2
				case "replace before":
					t.Fatal("invalid held path reached reader")
				case "replace during":
					replace()
				}
				return id, nil
			}
			source, proof, err := h.observeProof(reader, nil)
			if err == nil || source != "" || proof != (Proof{}) {
				t.Fatal("failed collection returned a proof")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "synthetic-token") {
				t.Fatal("untrusted diagnostic escaped")
			}
			if !errors.Is(h.Validate(), ErrChanged) {
				t.Fatal("failed observation did not latch invalidation")
			}
		})
	}
}

func TestProofConcurrentCaptureVerifyAndClose(t *testing.T) {
	h := holdFixture(t, newFixture(t))
	source, proof, err := h.observeProof(syntheticReader, nil)
	must(t, err)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, _, err := h.observeProof(syntheticReader, &proofExpectation{source, proof})
			if err != nil && !errors.Is(err, ErrClosed) {
				t.Errorf("observe: %v", err)
			}
			if err := h.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		})
	}
	wg.Wait()
	for _, closed := range []*HeldSource{nil, {}, h} {
		if _, _, err := closed.CaptureProof(); !errors.Is(err, ErrClosed) {
			t.Fatal("closed capture accepted")
		}
		if err := closed.VerifyProof(source, proof); !errors.Is(err, ErrClosed) {
			t.Fatal("closed comparison accepted")
		}
	}
}

type failedMountReader struct{}

func (failedMountReader) Read([]byte) (int, error) {
	return 0, errors.New("untrusted mount reader detail")
}

func TestProofMountAttestationRejectsAmbiguity(t *testing.T) {
	id := objectID{deviceMajor: 8, deviceMinor: 1, mount: 36}
	good := "36 20 8:1 / /private\\040mount rw,relatime shared:3 unknown:7 - ext4 /dev/example rw\n"
	if !mountIsExt4(strings.NewReader(good), id) {
		t.Fatal("valid ext4 mount rejected")
	}
	for name, data := range map[string]string{
		"empty": "", "no newline": strings.TrimSuffix(good, "\n"),
		"wrong mount":       strings.Replace(good, "36 ", "37 ", 1),
		"wrong device":      strings.Replace(good, "8:1", "8:2", 1),
		"ext3 same magic":   strings.Replace(good, "ext4", "ext3", 1),
		"overlay":           strings.Replace(good, "ext4", "overlay", 1),
		"duplicate":         good + good,
		"missing separator": strings.Replace(good, " - ", " ", 1),
		"truncated record":  "36 20 8:1 /\n",
		"extra field":       strings.TrimSuffix(good, "\n") + " extra\n",
		"noncanonical id":   "0" + good,
		"oversized":         strings.Repeat("x", maxMountInfoBytes) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if mountIsExt4(strings.NewReader(data), id) {
				t.Fatal("unsafe mount view accepted")
			}
		})
	}
	if mountIsExt4(failedMountReader{}, id) {
		t.Fatal("read error accepted")
	}
}
