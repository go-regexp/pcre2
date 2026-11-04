package corpus

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"
)

// caseJSON is the on-disk form of a Case. Input and expected output are
// arbitrary bytes (the test files contain Latin-1 and invalid UTF-8 on
// purpose); JSON strings cannot carry those, so text that is not valid UTF-8
// is stored base64-encoded in the *_b64 field instead.
type caseJSON struct {
	ID          string `json:"id"`
	Kind        Kind   `json:"kind"`
	Line        int    `json:"line"`
	Input       string `json:"input,omitempty"`
	InputB64    string `json:"input_b64,omitempty"`
	Expected    string `json:"expected,omitempty"`
	ExpectedB64 string `json:"expected_b64,omitempty"`
	Excluded    string `json:"excluded,omitempty"`
}

func splitText(s string) (plain, b64 string) {
	if utf8.ValidString(s) {
		return s, ""
	}
	return "", base64.StdEncoding.EncodeToString([]byte(s))
}

func joinText(plain, b64 string) (string, error) {
	if b64 == "" {
		return plain, nil
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	return string(b), err
}

// MarshalJSON implements json.Marshaler.
func (c Case) MarshalJSON() ([]byte, error) {
	j := caseJSON{ID: c.ID, Kind: c.Kind, Line: c.Line, Excluded: c.Excluded}
	j.Input, j.InputB64 = splitText(c.Input)
	j.Expected, j.ExpectedB64 = splitText(c.Expected)
	return encodeNoHTML(j, "")
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *Case) UnmarshalJSON(b []byte) error {
	var j caseJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	in, err := joinText(j.Input, j.InputB64)
	if err != nil {
		return err
	}
	exp, err := joinText(j.Expected, j.ExpectedB64)
	if err != nil {
		return err
	}
	*c = Case{ID: j.ID, Kind: j.Kind, Line: j.Line, Input: in, Expected: exp, Excluded: j.Excluded}
	return nil
}

// encodeNoHTML marshals v without escaping <, > and & (readable diffs).
func encodeNoHTML(v any, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
