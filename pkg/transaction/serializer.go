package transaction

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sort"
)

type ContractDataType byte

// Types supported by the serializer for this Virtual Machine
const (
	TypeNull    ContractDataType = 0
	TypeBool    ContractDataType = 1
	TypeInt32   ContractDataType = 2
	TypeInt64   ContractDataType = 3
	TypeString  ContractDataType = 4
	TypeBytes   ContractDataType = 5
	TypeArray   ContractDataType = 6
	TypeMap     ContractDataType = 7
	TypeFloat32 ContractDataType = 8
	TypeFloat64 ContractDataType = 9
)

// This Special set of Types need to be encoded using the memory address, because the runtime doesn't support them as "usual"
// the WASM runtime will need a pointer to the memory address, so we can't serialize them as usual
var VMPointerMemoryTypes = []ContractDataType{
	// TODO: Add more types as needed! Need to evaluate if we need to add more types here
	TypeString,
}

// Serialized data represents the encoded data of the Virtual Machine
type SerializedData struct {
	Type   ContractDataType
	Length uint32
	Data   []byte
}

func Encode(data interface{}) ([]byte, error) {
	// Basically the first 5 bytes are the type and the length

	val := reflect.ValueOf(data)
	if val.Kind() == reflect.Slice && val.Type() != reflect.TypeOf([]byte(nil)) {
		result := []byte{byte(TypeArray)}

		arrLen := make([]byte, 4)
		binary.BigEndian.PutUint32(arrLen, uint32(val.Len()))
		result = append(result, arrLen...)
		sizePos := len(result)
		result = append(result, make([]byte, 4)...)

		totalSize := 0
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i).Interface()
			elemEnc, err := Encode(elem)
			if err != nil {
				return nil, fmt.Errorf("failed to encode element: %w", err)
			}
			result = append(result, elemEnc...)
			totalSize += len(elemEnc)
		}
		binary.BigEndian.PutUint32(result[sizePos:], uint32(totalSize))
		return result, nil
	}
	// The rest is the data itself
	switch v := data.(type) {
	// Handling specific case for nil
	case nil:
		return []byte{byte(TypeNull), 0, 0, 0, 0}, nil
	case bool:
		b := []byte{byte(TypeBool), 0, 0, 0, 1}
		// True or false?
		if v {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
		return b, nil
	// The lengendary int32!!
	case int32:
		b := make([]byte, 9)
		b[0] = byte(TypeInt32)
		binary.BigEndian.PutUint32(b[1:5], 4)
		binary.BigEndian.PutUint32(b[5:], uint32(v))
		return b, nil
	case int64:
		b := make([]byte, 13)
		b[0] = byte(TypeInt64)
		binary.BigEndian.PutUint32(b[1:5], 8)
		binary.BigEndian.PutUint64(b[5:], uint64(v))
		return b, nil
	// Handling string
	case string:
		data := []byte(v)
		b := make([]byte, 5+len(data))
		b[0] = byte(TypeString)
		binary.BigEndian.PutUint32(b[1:5], uint32(len(data)))
		copy(b[5:], data)
		return b, nil
	case []byte:
		b := make([]byte, 5+len(v))
		b[0] = byte(TypeBytes)
		binary.BigEndian.PutUint32(b[1:5], uint32(len(v)))
		copy(b[5:], v)
		return b, nil
	case float32:
		b := make([]byte, 9)
		b[0] = byte(TypeFloat32)
		binary.BigEndian.PutUint32(b[1:5], 4)
		binary.BigEndian.PutUint32(b[5:], math.Float32bits(v))
		return b, nil
	case float64:
		b := make([]byte, 13)
		b[0] = byte(TypeFloat64)
		binary.BigEndian.PutUint32(b[1:5], 8)
		binary.BigEndian.PutUint64(b[5:], math.Float64bits(v))
		return b, nil
	// This is the only supported map type for now
	case map[string]interface{}:
		// Sort the keys to ensure consistent order!
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// First byte to determine the type!
		result := []byte{byte(TypeMap)}
		mapLen := make([]byte, 4)
		// How many keys are there?
		binary.BigEndian.PutUint32(mapLen, uint32(len(keys)))
		result = append(result, mapLen...)
		// Now we need to store the size of the map
		sizePos := len(result)
		result = append(result, make([]byte, 4)...)
		totalSize := 0
		for _, k := range keys {
			// Encode the key
			keyEnc, err := Encode(k)
			if err != nil {
				return nil, fmt.Errorf("failed to encode key: %w", err)
			}
			// Append the key to the result
			result = append(result, keyEnc...)
			// Add the size of the key to the total size
			totalSize += len(keyEnc)
			// Encode the value!
			valEnc, err := Encode(v[k])
			if err != nil {
				return nil, fmt.Errorf("failed to encode value: %w", err)
			}
			// Append the value to the result
			result = append(result, valEnc...)
			// Add the size of the value to the total size
			totalSize += len(valEnc)
		}
		// Store the total size of the map
		binary.BigEndian.PutUint32(result[sizePos:], uint32(totalSize))
		return result, nil
	}
	return nil, fmt.Errorf("unsupported type: %T", data)
}

func Decode(data []byte) (interface{}, error) {
	// First 5 bytes are the type and the length, so we need at least 5 bytes!
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short to decode")
	}

	dataType := ContractDataType(data[0])
	length := binary.BigEndian.Uint32(data[1:5])

	switch dataType {
	case TypeNull:
		return nil, nil
	case TypeBool:
		if length != 1 {
			return nil, fmt.Errorf("bool length must be 1, got %d", length)
		}
		return data[5] != 0, nil
	case TypeInt32:
		if length != 4 {
			return nil, fmt.Errorf("int32 length must be 4, got %d", length)
		}
		return int32(binary.BigEndian.Uint32(data[5:])), nil
	case TypeInt64:
		if length != 8 {
			return nil, fmt.Errorf("int64 length must be 8, got %d", length)
		}
		return int64(binary.BigEndian.Uint64(data[5:])), nil
	case TypeString:
		if length != uint32(len(data[5:])) {
			return nil, fmt.Errorf("string length mismatch: expected %d, got %d", length, len(data[5:]))
		}
		return string(data[5:]), nil
	case TypeBytes:
		if length != uint32(len(data[5:])) {
			return nil, fmt.Errorf("bytes length mismatch: expected %d, got %d", length, len(data[5:]))
		}
		return data[5:], nil
	case TypeFloat32:
		if length != 4 {
			return nil, fmt.Errorf("float32 length must be 4, got %d", length)
		}
		return math.Float32frombits(binary.BigEndian.Uint32(data[5:])), nil
	case TypeFloat64:
		if length != 8 {
			return nil, fmt.Errorf("float64 length must be 8, got %d", length)
		}
		return math.Float64frombits(binary.BigEndian.Uint64(data[5:])), nil
	case TypeMap:
		numEntries := binary.BigEndian.Uint32(data[1:5])
		totalSize := binary.BigEndian.Uint32(data[5:9])
		if len(data) < 9+int(totalSize) {
			return nil, fmt.Errorf("map data too short: expected %d, got %d", 9+int(totalSize), len(data))
		}

		result := make(map[string]interface{})
		offset := 9
		for i := uint32(0); i < numEntries; i++ {
			keySize := binary.BigEndian.Uint32(data[offset+1 : offset+5])
			keyIface, err := Decode(data[offset : offset+5+int(keySize)])
			if err != nil {
				return nil, fmt.Errorf("failed to decode key: %w", err)
			}
			key, ok := keyIface.(string)
			if !ok {
				return nil, fmt.Errorf("key is not a string: %T , error: %w", keyIface, err)
			}
			offset += 5 + int(keySize)
			valueSize := binary.BigEndian.Uint32(data[offset+1 : offset+5])
			valueIface, err := Decode(data[offset : offset+5+int(valueSize)])
			if err != nil {
				return nil, fmt.Errorf("failed to decode value: %w", err)
			}
			offset += 5 + int(valueSize)
			result[key] = valueIface
		}
		return result, nil
	case TypeArray:
		numElements := binary.BigEndian.Uint32(data[1:5])
		totalSize := binary.BigEndian.Uint32(data[5:9])
		if len(data) < 9+int(totalSize) {
			return nil, fmt.Errorf("array data too short: expected %d, got %d", 9+int(totalSize), len(data))
		}

		result := make([]interface{}, numElements)
		offset := 9

		for i := uint32(0); i < numElements; i++ {
			valueSize := binary.BigEndian.Uint32(data[offset+1 : offset+5])
			elem, err := Decode(data[offset : offset+5+int(valueSize)])
			if err != nil {
				return nil, fmt.Errorf("failed to decode element: %w", err)
			}
			result[i] = elem
			offset += 5 + int(valueSize)
		}
		// Convert the result to the correct type

		return result, nil
	}
	return nil, fmt.Errorf("unsupported type: %d", dataType)
}

func GetType(data []byte) (ContractDataType, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("data too short to get type")
	}
	// The first byte is the type! Let's return it!
	return ContractDataType(data[0]), nil
}
