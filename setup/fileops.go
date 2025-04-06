package setup

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// changeValueInFile applies changes to filepath, changes are pairs of [lookup, value]
// All lines in filePath matching `lookup = ...` will be replaced with `lookup = value`
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
			lookup := change[0]
			replace := change[1]
			if strings.HasPrefix(trimmed, lookup+" = ") {
				parts := strings.Split(line, " = ")
				if len(parts) != 2 || parts[0] != lookup {
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

// updateZeroHashesInFile updates the zero hashes in the file at path.
// It looks for a line starting with "zero_hashes = " and replaces all lines after it
// until the line starting with ")" (which does not change) with the new hashes.
func updateZeroHashesInFile(path string, hashes [][]byte) error {
	newHashes := formatAsStringConcatenation(hashes, 12)

	file, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", path, err)
	}

	var firstLineIndexToChange, lastLineIndexToChange int
	for i, line := range strings.Split(string(file), "\n") {
		trimmed := strings.TrimLeft(line, " \t\n\r")

		if strings.HasPrefix(trimmed, "zero_hashes = ") {
			firstLineIndexToChange = i + 1
			continue
		}

		if firstLineIndexToChange > 0 {
			if strings.HasPrefix(trimmed, ")") {
				lastLineIndexToChange = i - 1
				break
			}
		}
	}

	if firstLineIndexToChange > 0 && lastLineIndexToChange > firstLineIndexToChange {
		lines := strings.Split(string(file), "\n")
		newLines := append(lines[:firstLineIndexToChange], newHashes)
		newLines = append(newLines, lines[lastLineIndexToChange+1:]...)
		err = os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
		if err != nil {
			return fmt.Errorf("error writing %s: %v", path, err)
		}
	} else {
		return fmt.Errorf("zero_hashes not found in file %s", path)
	}
	return nil
}
