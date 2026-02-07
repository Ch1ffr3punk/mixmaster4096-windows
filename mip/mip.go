package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	filenameLen  = 12
	boundaryLen  = 24
	lineWidth    = 76
	crlf         = "\r\n"
	dashes       = "--"
)

func generateRandomString(n int) (string, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	for i := 0; i < n; i++ {
		bytes[i] = alphanumeric[int(bytes[i])%len(alphanumeric)]
	}
	return string(bytes), nil
}

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
	to := flag.String("t", "", "To: address (email recipient)")
	subject := flag.String("s", "", "Subject: line")
	newsgroups := flag.String("n", "", "Newsgroups: (optional, for Usenet posts)")
	help := flag.Bool("h", false, "Show help")
	helpLong := flag.Bool("help", false, "Show help")
	
	flag.Usage = func() {
		printUsage()
	}
	
	flag.Parse()

	if *help || *helpLong {
		printUsage()
		os.Exit(0)
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		printUsage()
		os.Exit(1)
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\r\n", err)
		os.Exit(1)
	}

	if len(data) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Input is empty\r\n")
		os.Exit(1)
	}

	var contentType, extension string
	if len(data) >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && 
		data[3] == 0x47 && data[4] == 0x0D && data[5] == 0x0A && 
		data[6] == 0x1A && data[7] == 0x0A {
		contentType = "image/png"
		extension = ".png"
	} else if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
		contentType = "image/jpeg"
		extension = ".jpg"
	} else {
		fmt.Fprintf(os.Stderr, "Error: File type not recognized. Only PNG and JPEG are supported.\r\n")
		os.Exit(1)
	}

	boundarySuffix, err := generateRandomString(boundaryLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating boundary: %v\r\n", err)
		os.Exit(1)
	}

	boundary := boundarySuffix

	filename, err := generateRandomString(filenameLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating filename: %v\r\n", err)
		os.Exit(1)
	}

	fullFilename := filename + extension

	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	// Header
	writer.WriteString("To: ")
	writer.WriteString(*to)
	writer.WriteString(crlf)

	writer.WriteString("Subject: ")
	writer.WriteString(*subject)
	writer.WriteString(crlf)

	if *newsgroups != "" {
		writer.WriteString("Newsgroups: ")
		writer.WriteString(*newsgroups)
		writer.WriteString(crlf)
	}

	writer.WriteString("MIME-Version: 1.0")
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Type: multipart/mixed; boundary=\"")
	writer.WriteString(boundary)
	writer.WriteString("\"")
	writer.WriteString(crlf)
	
	writer.WriteString(crlf)
	
	writer.WriteString("This is a multi-part message in MIME format.")
	writer.WriteString(crlf)
	
	writer.WriteString("--")
	writer.WriteString(boundary)
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Type: text/plain; charset=UTF-8")
	writer.WriteString(crlf)
	writer.WriteString("Content-Transfer-Encoding: 7bit")
	writer.WriteString(crlf)
	writer.WriteString(crlf)
	
	writer.WriteString("(Your message goes here.)")
	writer.WriteString(crlf)
	
	writer.WriteString("--")
	writer.WriteString(boundary)
	writer.WriteString(crlf)
	
	// Bildteil
	writer.WriteString("Content-Type: ")
	writer.WriteString(contentType)
	writer.WriteString("; name=\"")
	writer.WriteString(fullFilename)
	writer.WriteString("\"")
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Disposition: attachment; filename=\"")
	writer.WriteString(fullFilename)
	writer.WriteString("\"")
	writer.WriteString(crlf)
	
	writer.WriteString("Content-Transfer-Encoding: base64")
	writer.WriteString(crlf)
	writer.WriteString(crlf)

	// Base64-encoded image data
	encoder := base64.NewEncoder(base64.StdEncoding, &lineBreaker{w: writer})
	_, err = encoder.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during base64 encoding: %v\r\n", err)
		os.Exit(1)
	}
	encoder.Close()

	writer.WriteString(crlf)
	writer.WriteString("--")
	writer.WriteString(boundary)
	writer.WriteString("--")
	writer.WriteString(crlf)
}
