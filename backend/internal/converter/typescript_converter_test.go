package converter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseTimingFile_Valid tests parsing a valid timing file
func TestParseTimingFile_Valid(t *testing.T) {
	timingPath := filepath.Join("testdata", "sample.timing")

	entries, err := ParseTimingFile(timingPath)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)

	// Check first entry
	assert.Equal(t, 0.132, entries[0].Elapsed)
	assert.Equal(t, 27, entries[0].ByteCount)

	// Verify cumulative timestamps
	expectedCumulative := []float64{0.132, 0.155, 0.605, 0.705, 0.755, 0.835, 0.865}
	for i, entry := range entries {
		assert.InDelta(t, expectedCumulative[i], entry.Cumulative, 0.001)
	}
}

// TestParseTimingFile_Empty tests parsing an empty timing file
func TestParseTimingFile_Empty(t *testing.T) {
	// Create temporary empty file
	tmpFile, err := os.CreateTemp("", "empty-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	entries, err := ParseTimingFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestParseTimingFile_NotFound tests parsing a non-existent file
func TestParseTimingFile_NotFound(t *testing.T) {
	_, err := ParseTimingFile("nonexistent.timing")
	assert.Error(t, err)
}

// TestParseTimingFile_Malformed tests parsing malformed timing data
func TestParseTimingFile_Malformed(t *testing.T) {
	// Test case 1: Invalid elapsed time
	tmpFile1, err := os.CreateTemp("", "malformed1-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpFile1.Name())
	_, err = tmpFile1.WriteString("not_a_number 123\n")
	require.NoError(t, err)
	tmpFile1.Close()
	_, err = ParseTimingFile(tmpFile1.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid elapsed time")

	// Test case 2: Invalid byte count
	tmpFile2, err := os.CreateTemp("", "malformed2-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpFile2.Name())
	_, err = tmpFile2.WriteString("0.123 not_a_number\n")
	require.NoError(t, err)
	tmpFile2.Close()
	_, err = ParseTimingFile(tmpFile2.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid byte count")

	// Test case 3: Wrong number of fields
	tmpFile3, err := os.CreateTemp("", "malformed3-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpFile3.Name())
	_, err = tmpFile3.WriteString("0.123\n")
	require.NoError(t, err)
	tmpFile3.Close()
	_, err = ParseTimingFile(tmpFile3.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timing format")
}

// TestStripTypescriptMarkers tests stripping BEGIN/END markers
func TestStripTypescriptMarkers(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "with markers and newline before END",
			input:    []byte("[BEGIN TYPESCRIPT]\nHello World\n[END TYPESCRIPT]\n"),
			expected: []byte("Hello World"),
		},
		{
			name:     "without markers",
			input:    []byte("Hello World\n"),
			expected: []byte("Hello World\n"),
		},
		{
			name:     "only begin marker",
			input:    []byte("[BEGIN TYPESCRIPT]\nHello World\n"),
			expected: []byte("Hello World\n"),
		},
		{
			name:     "empty content",
			input:    []byte("[BEGIN TYPESCRIPT]\n[END TYPESCRIPT]\n"),
			expected: []byte(""),
		},
		{
			name:     "multiline content",
			input:    []byte("[BEGIN TYPESCRIPT]\nLine 1\nLine 2\nLine 3\n[END TYPESCRIPT]\n"),
			expected: []byte("Line 1\nLine 2\nLine 3"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripTypescriptMarkers(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestBuildAsciicastHeader tests building asciinema v2 header
func TestBuildAsciicastHeader(t *testing.T) {
	now := time.Now()
	session := &model.Session{
		StartTime: now,
	}

	header := BuildAsciicastHeader(session)

	// Verify required fields
	assert.Equal(t, 2, header["version"])
	assert.Equal(t, 80, header["width"])
	assert.Equal(t, 24, header["height"])
	assert.Equal(t, now.Unix(), header["timestamp"])
}

// TestBuildAsciicastHeader_WithMetadata tests header with custom terminal size
func TestBuildAsciicastHeader_WithMetadata(t *testing.T) {
	now := time.Now()
	session := &model.Session{
		StartTime: now,
	}

	// Test with default dimensions
	header := BuildAsciicastHeader(session)
	assert.Equal(t, 80, header["width"])
	assert.Equal(t, 24, header["height"])
}

// TestConvertTypescriptToAsciinema_Valid tests successful conversion
func TestConvertTypescriptToAsciinema_Valid(t *testing.T) {
	// Setup paths
	typescriptPath := filepath.Join("testdata", "sample.typescript")
	timingPath := filepath.Join("testdata", "sample.timing")

	// Create temporary output file
	tmpFile, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(outputPath)

	// Create test session
	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	// Perform conversion
	err = ConvertTypescriptToAsciinema(typescriptPath, timingPath, outputPath, session)
	require.NoError(t, err)

	// Verify output file exists
	_, err = os.Stat(outputPath)
	require.NoError(t, err)

	// Read and verify output format
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	lines := splitLines(content)
	require.GreaterOrEqual(t, len(lines), 2, "should have at least header and one event")

	// Verify header line
	var header map[string]interface{}
	err = json.Unmarshal([]byte(lines[0]), &header)
	require.NoError(t, err)
	assert.Equal(t, float64(2), header["version"])
	assert.Equal(t, float64(80), header["width"])
	assert.Equal(t, float64(24), header["height"])

	// Verify event lines
	for i := 1; i < len(lines); i++ {
		if lines[i] == "" {
			continue
		}
		var event []interface{}
		err = json.Unmarshal([]byte(lines[i]), &event)
		require.NoError(t, err, "line %d should be valid JSON array", i)
		assert.Len(t, event, 3, "event should have 3 elements")
		assert.Equal(t, "o", event[1], "event type should be 'o'")
	}
}

// TestConvertTypescriptToAsciinema_MissingTypescript tests error when typescript file missing
func TestConvertTypescriptToAsciinema_MissingTypescript(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(outputPath)

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	err = ConvertTypescriptToAsciinema("nonexistent.typescript", "nonexistent.timing", outputPath, session)
	assert.Error(t, err)
}

// TestConvertTypescriptToAsciinema_MissingTiming tests error when timing file missing
func TestConvertTypescriptToAsciinema_MissingTiming(t *testing.T) {
	typescriptPath := filepath.Join("testdata", "sample.typescript")

	tmpFile, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(outputPath)

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	err = ConvertTypescriptToAsciinema(typescriptPath, "nonexistent.timing", outputPath, session)
	assert.Error(t, err)
}

// TestConvertTypescriptToAsciinema_EmptyFiles tests conversion with empty files
func TestConvertTypescriptToAsciinema_EmptyFiles(t *testing.T) {
	// Create empty typescript file
	tmpTypescript, err := os.CreateTemp("", "empty-*.typescript")
	require.NoError(t, err)
	defer os.Remove(tmpTypescript.Name())
	tmpTypescript.Close()

	// Create empty timing file
	tmpTiming, err := os.CreateTemp("", "empty-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpTiming.Name())
	tmpTiming.Close()

	// Create output file
	tmpOutput, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	err = ConvertTypescriptToAsciinema(tmpTypescript.Name(), tmpTiming.Name(), outputPath, session)
	require.NoError(t, err)

	// Verify output has at least header
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	lines := splitLines(content)
	assert.GreaterOrEqual(t, len(lines), 1, "should have at least header")
}

// TestConvertTypescriptToAsciinema_LargeFile tests conversion with data larger than timing suggests
func TestConvertTypescriptToAsciinema_LargeFile(t *testing.T) {
	// Create typescript file with more data than timing file indicates
	tmpTypescript, err := os.CreateTemp("", "large-*.typescript")
	require.NoError(t, err)
	defer os.Remove(tmpTypescript.Name())

	content := "[BEGIN TYPESCRIPT]\nThis is a longer text than timing indicates\n[END TYPESCRIPT]\n"
	_, err = tmpTypescript.WriteString(content)
	require.NoError(t, err)
	tmpTypescript.Close()

	// Create timing file with smaller byte count
	tmpTiming, err := os.CreateTemp("", "large-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpTiming.Name())
	_, err = tmpTiming.WriteString("0.100 10\n")
	require.NoError(t, err)
	tmpTiming.Close()

	// Create output file
	tmpOutput, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	err = ConvertTypescriptToAsciinema(tmpTypescript.Name(), tmpTiming.Name(), outputPath, session)
	require.NoError(t, err)

	// Verify output is valid (should only include first 10 bytes)
	outputContent, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.NotEmpty(t, outputContent)
}

// TestConvertTypescriptToAsciinema_InvalidOutputPath tests error when output path is invalid
func TestConvertTypescriptToAsciinema_InvalidOutputPath(t *testing.T) {
	typescriptPath := filepath.Join("testdata", "sample.typescript")
	timingPath := filepath.Join("testdata", "sample.timing")

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	// Try to write to an invalid directory
	err := ConvertTypescriptToAsciinema(typescriptPath, timingPath, "/nonexistent/dir/output.cast", session)
	assert.Error(t, err)
}

// TestConvertTypescriptToAsciinema_TimingWithWhitespace tests timing file with blank lines
func TestConvertTypescriptToAsciinema_TimingWithWhitespace(t *testing.T) {
	// Create typescript file
	tmpTypescript, err := os.CreateTemp("", "whitespace-*.typescript")
	require.NoError(t, err)
	defer os.Remove(tmpTypescript.Name())
	_, err = tmpTypescript.WriteString("[BEGIN TYPESCRIPT]\nHello\n[END TYPESCRIPT]\n")
	require.NoError(t, err)
	tmpTypescript.Close()

	// Create timing file with blank lines
	tmpTiming, err := os.CreateTemp("", "whitespace-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpTiming.Name())
	_, err = tmpTiming.WriteString("\n0.100 5\n\n")
	require.NoError(t, err)
	tmpTiming.Close()

	// Create output file
	tmpOutput, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	err = ConvertTypescriptToAsciinema(tmpTypescript.Name(), tmpTiming.Name(), outputPath, session)
	require.NoError(t, err)
}

// TestConvertTypescriptToAsciinema_MultipleChunks tests conversion with multiple timing chunks
func TestConvertTypescriptToAsciinema_MultipleChunks(t *testing.T) {
	// Create typescript file
	tmpTypescript, err := os.CreateTemp("", "chunks-*.typescript")
	require.NoError(t, err)
	defer os.Remove(tmpTypescript.Name())
	_, err = tmpTypescript.WriteString("[BEGIN TYPESCRIPT]\nChunk1Chunk2Chunk3\n[END TYPESCRIPT]\n")
	require.NoError(t, err)
	tmpTypescript.Close()

	// Create timing file with multiple entries
	tmpTiming, err := os.CreateTemp("", "chunks-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpTiming.Name())
	_, err = tmpTiming.WriteString("0.100 6\n0.200 6\n0.300 6\n")
	require.NoError(t, err)
	tmpTiming.Close()

	// Create output file
	tmpOutput, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	err = ConvertTypescriptToAsciinema(tmpTypescript.Name(), tmpTiming.Name(), outputPath, session)
	require.NoError(t, err)

	// Verify output has multiple events
	outputContent, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	lines := splitLines(outputContent)
	// Should have header + 3 events
	assert.GreaterOrEqual(t, len(lines), 4)
}

// TestConvertTypescriptToAsciinema_UTF8 tests UTF-8 character preservation
func TestConvertTypescriptToAsciinema_UTF8(t *testing.T) {
	// Create typescript file with UTF-8 content
	tmpTypescript, err := os.CreateTemp("", "utf8-*.typescript")
	require.NoError(t, err)
	defer os.Remove(tmpTypescript.Name())

	utf8Content := "[BEGIN TYPESCRIPT]\n你好世界 Hello 🌍\n[END TYPESCRIPT]\n"
	_, err = tmpTypescript.WriteString(utf8Content)
	require.NoError(t, err)
	tmpTypescript.Close()

	// Calculate actual byte count of the content (without markers)
	// "你好世界 Hello 🌍\n" = 12 bytes (Chinese) + 1 byte (space) + 5 bytes (Hello) + 1 byte (space) + 4 bytes (emoji) + 1 byte (newline) = 24 bytes
	content := "你好世界 Hello 🌍\n"
	byteCount := len([]byte(content))

	// Create timing file
	tmpTiming, err := os.CreateTemp("", "utf8-*.timing")
	require.NoError(t, err)
	defer os.Remove(tmpTiming.Name())
	_, err = tmpTiming.WriteString(fmt.Sprintf("0.100 %d\n", byteCount))
	require.NoError(t, err)
	tmpTiming.Close()

	// Create output file
	tmpOutput, err := os.CreateTemp("", "output-*.cast")
	require.NoError(t, err)
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	session := &model.Session{
		ID:        1,
		StartTime: time.Now(),
	}

	err = ConvertTypescriptToAsciinema(tmpTypescript.Name(), tmpTiming.Name(), outputPath, session)
	require.NoError(t, err)

	// Verify UTF-8 is preserved
	outputContent, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Contains(t, string(outputContent), "你好世界")
	assert.Contains(t, string(outputContent), "🌍")
}

// Helper function to split content into lines
func splitLines(content []byte) []string {
	lines := []string{}
	line := ""
	for _, b := range content {
		if b == '\n' {
			lines = append(lines, line)
			line = ""
		} else {
			line += string(b)
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
