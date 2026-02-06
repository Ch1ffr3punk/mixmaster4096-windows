package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// alphanumeric characters for random filename (lowercase only)
	alphanumeric = "abcdefghijklmnopqrstuvwxyz0123456789"
	filenameLen  = 12
	lineWidth    = 76 // RFC 2045: MIME base64 lines should not exceed 76 characters
	crlf         = "\r\n"
)

// generateRandomFilename creates a random 12-character alphanumeric filename with extension
func generateRandomFilename(extension string) (string, error) {
	bytes := make([]byte, filenameLen)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	for i := 0; i < filenameLen; i++ {
		bytes[i] = alphanumeric[int(bytes[i])%len(alphanumeric)]
	}

	return string(bytes) + extension, nil
}

// lineBreaker wraps an io.Writer and inserts CRLF every lineWidth characters
type lineBreaker struct {
	w       io.Writer
	lineLen int
}

func (l *lineBreaker) Write(p []byte) (n int, err error) {
	for _, b := range p {
		if l.lineLen == lineWidth {
			_, err = l.w.Write([]byte(crlf))
			if err != nil {
				return n, err
			}
			l.lineLen = 0
		}
		_, err = l.w.Write([]byte{b})
		if err != nil {
			return n, err
		}
		n++
		l.lineLen++
	}
	return n, nil
}

func printUsage() {
	programName := os.Args[0]
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] < input_image\r\n", programName)
	fmt.Fprintf(os.Stderr, "Convert PNG/JPEG images to MIME-compliant email or Usenet messages.\r\n\r\n")
	fmt.Fprintf(os.Stderr, "Options:\r\n")
	fmt.Fprintf(os.Stderr, "  -t string    To: address (email recipient)\r\n")
	fmt.Fprintf(os.Stderr, "  -s string    Subject: line\r\n")
	fmt.Fprintf(os.Stderr, "  -n string    Newsgroups: (optional, for Usenet posts)\r\n")
	fmt.Fprintf(os.Stderr, "  -h, --help   Show this help message\r\n\r\n")
	fmt.Fprintf(os.Stderr, "Example:\r\n")
	fmt.Fprintf(os.Stderr, "  %s -t recipient@example.com -s \"My Image\" < image.png > message.txt\r\n\r\n", programName)
	fmt.Fprintf(os.Stderr, "The program reads from stdin and writes to stdout.\r\n")
}

func main() {
	// Define command line parameters
	to := flag.String("t", "", "To: address (email recipient)")
	subject := flag.String("s", "", "Subject: line")
	newsgroups := flag.String("n", "", "Newsgroups: (optional, for Usenet posts)")
	help := flag.Bool("h", false, "Show help")
	helpLong := flag.Bool("help", false, "Show help")
	
	// Custom usage function
	flag.Usage = func() {
		printUsage()
	}
	
	flag.Parse()

	// Check for help flag
	if *help || *helpLong {
		printUsage()
		os.Exit(0)
	}

	// Check if stdin has data (not a terminal)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		printUsage()
		os.Exit(1)
	}

	// Read entire input from stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\r\n", err)
		os.Exit(1)
	}

	if len(data) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Input is empty\r\n")
		os.Exit(1)
	}

	// Detect file type based on magic numbers
	var contentType, extension string
	
	// PNG signature: 89 50 4E 47 0D 0A 1A 0A
	if len(data) >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && 
		data[3] == 0x47 && data[4] == 0x0D && data[5] == 0x0A && 
		data[6] == 0x1A && data[7] == 0x0A {
		contentType = "image/png"
		extension = ".png"
	} else if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
		// JPEG/JFIF signature starts with FF D8
		contentType = "image/jpeg"
		extension = ".jpg"
	} else {
		fmt.Fprintf(os.Stderr, "Error: File type not recognized. Only PNG and JPEG are supported.\r\n")
		os.Exit(1)
	}

	// Generate random filename
	filename, err := generateRandomFilename(extension)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating filename: %v\r\n", err)
		os.Exit(1)
	}

	// Write headers and encoded data to stdout
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	// Write headers with CRLF line endings (RFC 822/2822 requirement)
	
	// To: header (always write, even if empty for Usenet)
	writer.WriteString("To: ")
	writer.WriteString(*to)
	writer.WriteString(crlf)

	// Subject: header (always write, even if empty)
	writer.WriteString("Subject: ")
	writer.WriteString(*subject)
	writer.WriteString(crlf)

	// Newsgroups: header (write only if provided)
	if *newsgroups != "" {
		writer.WriteString("Newsgroups: ")
		writer.WriteString(*newsgroups)
		writer.WriteString(crlf)
	}

	// Required MIME headers
	writer.WriteString("MIME-Version: 1.0")
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Type: ")
	writer.WriteString(contentType)
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Transfer-Encoding: base64")
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Description: ")
	writer.WriteString(strings.TrimSuffix(filename, extension))
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Disposition: inline; filename=")
	writer.WriteString(filename)
	writer.WriteString(crlf)

	// Blank line separating headers and body (RFC requirement)
	writer.WriteString(crlf)

	// Encode image data to base64 with line wrapping
	encoder := base64.NewEncoder(base64.StdEncoding, &lineBreaker{w: writer})
	_, err = encoder.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during base64 encoding: %v\r\n", err)
		os.Exit(1)
	}
	encoder.Close()

	// Final CRLF to end the message
	writer.WriteString(crlf)
}
