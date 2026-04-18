package infoplist

import (
	"fmt"
	"os"

	plTypes "github.com/AzozzALFiras/GoSigner/plist"
	"howett.net/plist"
)

// Read parses an Info.plist file and returns the structured data.
func Read(path string) (*plTypes.InfoPlistData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read info.plist: %w", err)
	}
	return ReadFromBytes(data)
}

// ReadFromBytes parses Info.plist from raw bytes.
func ReadFromBytes(data []byte) (*plTypes.InfoPlistData, error) {
	info := &plTypes.InfoPlistData{}
	_, err := plist.Unmarshal(data, info)
	if err != nil {
		return nil, fmt.Errorf("unmarshal info.plist: %w", err)
	}
	return info, nil
}

// ReadRaw parses an Info.plist into a generic map (for modification).
func ReadRaw(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	_, err := plist.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal info.plist: %w", err)
	}
	return result, nil
}
