package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// HandleJsonError processes JSON-related errors and returns a descriptive error message.
// It handles various types of JSON errors, including syntax errors, unexpected EOF,
// unmarshal type errors, unknown fields, empty body, and oversized body.
//
// Parameters:
// - err: The error to be processed.
//
// Returns:
// - A string containing a descriptive error message.
func HandleJsonError(err error) string {
	var syntaxError *json.SyntaxError
	var unmarshalTypeError *json.UnmarshalTypeError

	var msg string
	switch {
	case errors.As(err, &syntaxError):
		msg = fmt.Sprintf("body contains badly-formed json (at position %d), %s", syntaxError.Offset, syntaxError.Error())

	case errors.Is(err, io.ErrUnexpectedEOF):
		msg = "body contains badly-formed json"

	case errors.As(err, &unmarshalTypeError):
		msg = fmt.Sprintf("body contains an invalid value for the %q field (at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)

	case strings.HasPrefix(err.Error(), "json: unknown field "):
		fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
		msg = fmt.Sprintf("body contains unknown field %s", fieldName)

	case errors.Is(err, io.EOF):
		msg = "body must not be empty"

	case err.Error() == "http: request body too large":
		msg = "body must not be larger than 1MB"

	default:
		msg = err.Error()
	}
	return msg
}
