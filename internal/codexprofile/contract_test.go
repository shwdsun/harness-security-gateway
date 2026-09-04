package codexprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const expectedFingerprintV1 = "96ca4f1845f5ee673d7302fb938e698d1344435d62280b8174e31200738f143d"
const expectedFingerprintV2 = "d8ee4889edd0bac79fd8ee6278bf10c06a29b0dcdc743433ecad17a5cee0aa68"
const expectedMessagingInstructionFingerprintV1 = "1e4af42e7e6778a46cca4637eedf6cccb7f1b90556c867ecaf478db908720369"

func TestV1ContractAndFingerprintAreStable(t *testing.T) {
	contract := V1()
	if err := contract.Validate(); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := contract.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != expectedFingerprintV1 {
		t.Fatalf("V1 fingerprint = %q, want %q", fingerprint, expectedFingerprintV1)
	}
	if ContractFingerprintV1 != expectedFingerprintV1 {
		t.Fatalf("published V1 fingerprint = %q, want %q", ContractFingerprintV1, expectedFingerprintV1)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("V1 fingerprint length = %d", len(fingerprint))
	}
}

func TestV2ContractAndFingerprintAreStable(t *testing.T) {
	contract := V2()
	if err := contract.Validate(); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := contract.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != expectedFingerprintV2 || ContractFingerprintV2 != expectedFingerprintV2 {
		t.Fatalf("V2 fingerprint = %q, published = %q, want %q", fingerprint, ContractFingerprintV2, expectedFingerprintV2)
	}
	if contract.Runner.AdapterVersion != AdapterVersionV2 ||
		contract.Context.InstructionProfileRef != MessagingInstructionIDV1 ||
		contract.Context.InstructionProfileFingerprint != MessagingInstructionFingerprintV1 ||
		contract.Context.InstructionRole != "developer" ||
		contract.Context.InstructionInjection != "codex.config.developer_instructions" {
		t.Fatalf("V2 messaging context is not exact: %#v", contract)
	}
	if V1().Context.InstructionProfileRef != "" || V1().Context.InstructionProfileFingerprint != "" ||
		V1().Context.InstructionRole != "" || V1().Context.InstructionInjection != "" {
		t.Fatalf("V1 acquired V2 context: %#v", V1().Context)
	}
}

func TestMessagingInstructionProfileAndFingerprintAreStable(t *testing.T) {
	profile := MessagingInstructionV1()
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := profile.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != expectedMessagingInstructionFingerprintV1 ||
		MessagingInstructionFingerprintV1 != expectedMessagingInstructionFingerprintV1 {
		t.Fatalf("messaging instruction fingerprint = %q, published = %q, want %q", fingerprint, MessagingInstructionFingerprintV1, expectedMessagingInstructionFingerprintV1)
	}
	if strings.ContainsRune(profile.Text, '\x00') || strings.Contains(profile.Text, "\r") || len(profile.Text) > 4096 {
		t.Fatalf("messaging instruction text has an unsafe shape")
	}
	rawDigest := sha256.Sum256([]byte(profile.Text))
	if got := hex.EncodeToString(rawDigest[:]); got != MessagingInstructionTextSHA256V1 {
		t.Fatalf("messaging instruction text SHA-256 = %q, want %q", got, MessagingInstructionTextSHA256V1)
	}
	if len(profile.Text) != MessagingInstructionTextBytesV1 {
		t.Fatalf("messaging instruction text bytes = %d, want %d", len(profile.Text), MessagingInstructionTextBytesV1)
	}
	mutations := []MessagingInstructionProfile{
		{Schema: profile.Schema + "-changed", ID: profile.ID, Kind: profile.Kind, Text: profile.Text},
		{Schema: profile.Schema, ID: profile.ID + "-changed", Kind: profile.Kind, Text: profile.Text},
		{Schema: profile.Schema, ID: profile.ID, Kind: profile.Kind + "-changed", Text: profile.Text},
		{Schema: profile.Schema, ID: profile.ID, Kind: profile.Kind, Text: profile.Text + " changed"},
	}
	for index, changed := range mutations {
		if err := changed.Validate(); !errors.Is(err, ErrInvalidMessagingInstruction) {
			t.Fatalf("mutation %d error = %v", index, err)
		}
		changedFingerprint, err := fingerprintMessagingInstruction(changed)
		if err != nil {
			t.Fatalf("mutation %d fingerprint: %v", index, err)
		}
		if changedFingerprint == fingerprint {
			t.Fatalf("mutation %d did not change fingerprint", index)
		}
	}
}

func TestResolveAcceptsOnlySealedIDs(t *testing.T) {
	for _, want := range []Contract{V1(), V2()} {
		got, err := Resolve(want.ID)
		if err != nil || got != want {
			t.Fatalf("Resolve(%q) = %#v, %v", want.ID, got, err)
		}
	}
	for _, id := range []string{"", "codex.chatgpt-personal-v3", MessagingInstructionIDV1} {
		if _, err := Resolve(id); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Resolve(%q) error = %v, want ErrInvalid", id, err)
		}
	}
}

func TestV1RejectsAndFingerprintsEveryAuthorityMutation(t *testing.T) {
	testRejectsAndFingerprintsEveryContractMutation(t, V1())
}

func TestV2RejectsAndFingerprintsEveryAuthorityMutation(t *testing.T) {
	testRejectsAndFingerprintsEveryContractMutation(t, V2())
}

func testRejectsAndFingerprintsEveryContractMutation(t *testing.T, baseline Contract) {
	t.Helper()
	baselineFingerprint, err := fingerprint(baseline)
	if err != nil {
		t.Fatal(err)
	}

	mutations := 0
	visitStrings(reflect.ValueOf(baseline), "", func(path string, indexes []int) {
		mutations++
		changed := baseline
		field := reflect.ValueOf(&changed).Elem()
		for _, index := range indexes {
			field = field.Field(index)
		}
		field.SetString(field.String() + "-changed")

		if err := changed.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s mutation error = %v, want ErrInvalid", path, err)
		}
		changedFingerprint, err := fingerprint(changed)
		if err != nil {
			t.Fatalf("%s mutation fingerprint: %v", path, err)
		}
		if changedFingerprint == baselineFingerprint {
			t.Fatalf("%s mutation did not change fingerprint", path)
		}
	})
	if mutations == 0 {
		t.Fatal("contract contains no fingerprinted fields")
	}
}

func TestContractsContainNoOpenAuthorityContainersOrCredentialBytes(t *testing.T) {
	assertClosedType(t, reflect.TypeOf(V1()), "Contract")
	for _, contract := range []Contract{V1(), V2()} {
		encoded, err := jsonBytes(contract)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"token", "device_code", "account_id", "slot_ref", "generation",
			"source_identity", "/home/", "options", "metadata",
		} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("%s canonical contract contains forbidden authority or secret field %q", contract.ID, forbidden)
			}
		}
	}
}

func visitStrings(value reflect.Value, path string, visit func(string, []int)) {
	var walk func(reflect.Value, string, []int)
	walk = func(current reflect.Value, currentPath string, indexes []int) {
		for index := 0; index < current.NumField(); index++ {
			field := current.Field(index)
			name := current.Type().Field(index).Name
			fieldPath := name
			if currentPath != "" {
				fieldPath = currentPath + "." + name
			}
			fieldIndexes := append(append([]int(nil), indexes...), index)
			switch field.Kind() {
			case reflect.String:
				visit(fieldPath, fieldIndexes)
			case reflect.Struct:
				walk(field, fieldPath, fieldIndexes)
			default:
				panic("unexpected contract field kind " + field.Kind().String())
			}
		}
	}
	walk(value, path, nil)
}

func assertClosedType(t *testing.T, value reflect.Type, path string) {
	t.Helper()
	if value.Kind() != reflect.Struct {
		t.Fatalf("%s kind = %s, want struct", path, value.Kind())
	}
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		fieldPath := path + "." + field.Name
		switch field.Type.Kind() {
		case reflect.String:
		case reflect.Struct:
			assertClosedType(t, field.Type, fieldPath)
		default:
			t.Fatalf("%s kind = %s; maps, slices, pointers, and interfaces are forbidden", fieldPath, field.Type.Kind())
		}
	}
}

func jsonBytes(contract Contract) ([]byte, error) {
	return json.Marshal(contract)
}
