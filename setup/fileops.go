package setup

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

// changeValueInFile applies changes to filepath, changes are pairs of [lookup, value]
// The first line in filePath matching `search = ...` will be replaced with `lookup = value`
func changeValueInFile(filepath string, changes [][2]string) error {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
	lines := strings.Split(string(content), "\n")
	found := make([]bool, len(changes))
	fileModified := false
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t\n\r")
		for j, change := range changes {
			search := change[0]
			replace := change[1]
			if strings.HasPrefix(trimmed, search+" = ") {
				parts := strings.Split(line, " = ")
				if len(parts) != 2 || parts[0] != search {
					continue
				}
				found[j] = true
				if parts[1] != replace {
					lines[i] = parts[0] + " = " + replace
					fileModified = true
				}
				break
			}
		}
	}
	// report if any search string not found
	for i, change := range changes {
		if !found[i] {
			log.Printf("Search string %s not found in file %s\n", change[0], filepath)
		}
	}
	if fileModified {
		output := strings.Join(lines, "\n")
		err = os.WriteFile(filepath, []byte(output), 0644)
		if err != nil {
			return fmt.Errorf("error writing file: %w", err)
		}
	}
	return nil
}

// formatWithUnderscores formats a number with underscores every 3 digits
func formatWithUnderscores(num int) string {
	numStr := strconv.Itoa(num)
	n := len(numStr)
	var result strings.Builder
	for i, digit := range numStr {
		result.WriteByte(byte(digit))
		if (n-i-1)%3 == 0 && i != n-1 {
			result.WriteByte('_')
		}
	}
	return result.String()
}

// replaceInFile replaces in filepath all keys in mapping with their values
func replaceInFile(filepath string, mapping map[string]string) error {
	program, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filepath, err)
	}
	for key, value := range mapping {
		program = []byte(strings.ReplaceAll(string(program), key, value))
	}
	// overwrite the file
	err = os.WriteFile(filepath, program, 0644)
	if err != nil {
		return fmt.Errorf("error writing %s: %v", filepath, err)
	}
	return nil
}

// DecodeJSONFile decodes the JSON filepath into the given interface
func DecodeJSONFile(filepath string, v interface{}) {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("Error opening file %s: %v", filepath, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(v); err != nil {
		log.Fatalf("Error decoding file %s: %v", filepath, err)
	}
}

// encodeJSONFile encodes the given interface into the JSON filepath,
func encodeJSONFile(filepath string, v interface{}) {
	file, err := os.Create(filepath)
	if err != nil {
		log.Fatalf("Error opening file %s: %v", filepath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(v); err != nil {
		log.Fatalf("Error encoding file %s: %v", filepath, err)
	}
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	return nil
}
