package trustrecord

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	jsonv2 "github.com/go-json-experiment/json"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

var ErrUnsupportedProfile = errors.New("trust record: unsupported profile")

//go:embed boxedai-trust-record-v1.json
var schemaSource []byte

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaSource))
	if err != nil {
		return nil, fmt.Errorf("trust record: decode embedded schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://boxedai.dev/schema/trust-record-v1.json", doc); err != nil {
		return nil, fmt.Errorf("trust record: add embedded schema: %w", err)
	}
	sch, err := compiler.Compile("https://boxedai.dev/schema/trust-record-v1.json")
	if err != nil {
		return nil, fmt.Errorf("trust record: compile embedded schema: %w", err)
	}
	return sch, nil
})

func PinProfile(data []byte) error {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := jsonv2.Unmarshal(data, &header); err != nil {
		return fmt.Errorf("trust record: decode profile: %w", err)
	}
	if header.Schema != Profile {
		return fmt.Errorf("%w %q", ErrUnsupportedProfile, header.Schema)
	}
	return nil
}

func ValidateJSON(data []byte) error {
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("trust record: decode JSON: %w", err)
	}
	sch, err := compiledSchema()
	if err != nil {
		return err
	}
	if err := sch.Validate(value); err != nil {
		return fmt.Errorf("trust record: schema validation: %w", err)
	}
	return nil
}

func Decode(data []byte) (Record, error) {
	if err := PinProfile(data); err != nil {
		return Record{}, err
	}
	if err := ValidateJSON(data); err != nil {
		return Record{}, err
	}
	var record Record
	if err := jsonv2.Unmarshal(data, &record, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Record{}, fmt.Errorf("trust record: decode envelope: %w", err)
	}
	return record, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trust record: unexpected trailing JSON value")
		}
		return fmt.Errorf("trust record: decode trailing JSON: %w", err)
	}
	return nil
}
