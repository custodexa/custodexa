package converter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// TimingEntry represents a single timing entry
type TimingEntry struct {
	Elapsed    float64 // Relative elapsed time in seconds
	ByteCount  int     // Number of bytes in this chunk
	Cumulative float64 // Cumulative timestamp (calculated)
}

// ParseTimingFile parses a typescript timing file
// Format: "{elapsed_seconds} {byte_count}" per line
// Returns entries with cumulative timestamps calculated
func ParseTimingFile(path string) ([]TimingEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open timing file: %w", err)
	}
	defer file.Close()

	var entries []TimingEntry
	var cumulative float64

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid timing format at line %d: expected 2 fields, got %d", lineNum, len(parts))
		}

		// Parse elapsed time
		elapsed, err := strconv.ParseFloat(parts[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid elapsed time at line %d: %w", lineNum, err)
		}

		// Parse byte count
		byteCount, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid byte count at line %d: %w", lineNum, err)
		}

		// Calculate cumulative timestamp
		cumulative += elapsed

		entries = append(entries, TimingEntry{
			Elapsed:    elapsed,
			ByteCount:  byteCount,
			Cumulative: cumulative,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading timing file: %w", err)
	}

	return entries, nil
}

// StripTypescriptMarkers removes [BEGIN TYPESCRIPT] and [END TYPESCRIPT] markers
// BEGIN marker: "[BEGIN TYPESCRIPT]\n" (18 bytes)
// END marker: "[END TYPESCRIPT]\n" (17 bytes) - can appear with or without preceding newline
func StripTypescriptMarkers(data []byte) []byte {
	beginMarker := []byte("[BEGIN TYPESCRIPT]\n")
	endMarker := []byte("[END TYPESCRIPT]\n")
	endMarkerWithNewline := []byte("\n[END TYPESCRIPT]\n")

	// Remove begin marker if present
	if bytes.HasPrefix(data, beginMarker) {
		data = data[len(beginMarker):]
	}

	// Remove end marker if present (check with newline first)
	if bytes.HasSuffix(data, endMarkerWithNewline) {
		data = data[:len(data)-len(endMarkerWithNewline)]
	} else if bytes.HasSuffix(data, endMarker) {
		data = data[:len(data)-len(endMarker)]
	}

	return data
}

// BuildAsciicastHeader builds the asciinema v2 header
// Returns a map that can be JSON marshaled
func BuildAsciicastHeader(session *model.Session) map[string]interface{} {
	header := map[string]interface{}{
		"version":   2,
		"width":     80, // Default terminal width
		"height":    24, // Default terminal height
		"timestamp": session.StartTime.Unix(),
	}

	// TODO: In the future, we could read terminal dimensions from session metadata
	// if session.Metadata != nil && session.Metadata.Width > 0 {
	//     header["width"] = session.Metadata.Width
	// }

	return header
}

// ConvertTypescriptToAsciinema converts typescript+timing files to asciinema v2 format
// Input:
//   - typescriptPath: path to .typescript file
//   - timingPath: path to .timing file
//   - outputPath: path to write .cast file
//   - session: session metadata for header
//
// Output:
//   - Creates a .cast file in asciinema v2 format
func ConvertTypescriptToAsciinema(
	typescriptPath string,
	timingPath string,
	outputPath string,
	session *model.Session,
) error {
	// Parse timing file
	timingEntries, err := ParseTimingFile(timingPath)
	if err != nil {
		return fmt.Errorf("failed to parse timing file: %w", err)
	}

	// Read typescript file
	typescriptData, err := os.ReadFile(typescriptPath)
	if err != nil {
		return fmt.Errorf("failed to read typescript file: %w", err)
	}

	// Strip markers
	strippedData := StripTypescriptMarkers(typescriptData)

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Write header
	header := BuildAsciicastHeader(session)
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	if _, err := outFile.Write(headerJSON); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := outFile.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	// Process events
	offset := 0
	for _, timing := range timingEntries {
		// Extract chunk from typescript data
		if offset >= len(strippedData) {
			break // No more data
		}

		endOffset := offset + timing.ByteCount
		if endOffset > len(strippedData) {
			endOffset = len(strippedData)
		}

		chunk := strippedData[offset:endOffset]
		offset = endOffset

		// Build event: [timestamp, "o", data]
		event := []interface{}{
			timing.Cumulative,
			"o",
			string(chunk),
		}

		eventJSON, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}

		if _, err := outFile.Write(eventJSON); err != nil {
			return fmt.Errorf("failed to write event: %w", err)
		}
		if _, err := outFile.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}

	return nil
}
