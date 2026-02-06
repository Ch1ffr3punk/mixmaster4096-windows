package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "mime"
    "os"
    "strings"
)

func encodeMIMESubject(input string) string {
    if input == "" {
        return ""
    }
    
    // Encode using MIME B encoding
    encoded := mime.BEncoding.Encode("UTF-8", input)
    
    // For CLI output, we want single line but with proper spacing
    // Remove any existing newlines first
    encoded = strings.ReplaceAll(encoded, "\n", " ")
    
    // Replace "?=  =?" with "?= =?" (single space between parts)
    encoded = strings.ReplaceAll(encoded, "?=  =?", "?= =?")
    
    return encoded
}

func decodeMIMESubject(input string) string {
    if input == "" {
        return ""
    }
    
    // Clean up the input for proper decoding
    // Remove newlines and extra spaces
    input = strings.ReplaceAll(input, "\n", "")
    input = strings.TrimSpace(input)
    
    // Normalize spacing between encoded parts
    input = strings.ReplaceAll(input, "?=  =?", "?= =?")
    
    dec := new(mime.WordDecoder)
    decoded, err := dec.DecodeHeader(input)
    if err != nil {
        return "Error: Invalid MIME input - " + err.Error()
    }
    
    return decoded
}

// autoDetect checks if input looks like MIME encoded text
func autoDetect(input string) bool {
    trimmed := strings.TrimSpace(input)
    
    // Check for MIME encoded pattern: =?charset?encoding?encoded-text?=
    if strings.HasPrefix(trimmed, "=?") && strings.Contains(trimmed, "?=") {
        // Count occurrences of =?
        parts := strings.Split(trimmed, "=?")
        if len(parts) > 1 {
            return true
        }
    }
    
    return false
}

func main() {
    encodeFlag := flag.Bool("e", false, "Force encode input to MIME Base64")
    decodeFlag := flag.Bool("d", false, "Force decode MIME Base64 input")
    helpFlag := flag.Bool("h", false, "Show help")
    
    flag.Parse()
    
    if *helpFlag {
        fmt.Println("Mixmaster MIME Base64 Subject: Encoder/Decoder")
        fmt.Println("Usage: mse [OPTION]")
        fmt.Println("  -e    Force encode input (don't auto-detect)")
        fmt.Println("  -d    Force decode input (don't auto-detect)")
        fmt.Println("  -h    Show this help")
        fmt.Println("")
        fmt.Println("Without -e or -d, auto-detects whether to encode or decode.")
        fmt.Println("Reads from stdin, writes to stdout.")
        fmt.Println("All output is in a single line (for Mixmaster bug workaround).")
        os.Exit(0)
    }
    
    // Check if both flags are set
    if *encodeFlag && *decodeFlag {
        fmt.Fprintf(os.Stderr, "Error: Cannot use both -e and -d flags simultaneously\n")
        os.Exit(1)
    }
    
    // Read input from stdin
    var input string
    
    // Check if stdin has data
    stat, _ := os.Stdin.Stat()
    if (stat.Mode() & os.ModeCharDevice) == 0 {
        // Data is being piped to stdin
        reader := bufio.NewReader(os.Stdin)
        var builder strings.Builder
        
        for {
            line, err := reader.ReadString('\n')
            builder.WriteString(line)
            
            if err != nil {
                if err == io.EOF {
                    break
                }
                fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
                os.Exit(1)
            }
        }
        
        input = builder.String()
    } else {
        // No piped input, try to read from first non-flag argument
        if len(flag.Args()) > 0 {
            input = strings.Join(flag.Args(), " ")
        } else {
            // No input provided, show help
            fmt.Fprintf(os.Stderr, "No input provided. Use -h for help.\n")
            os.Exit(1)
        }
    }
    
    // Trim whitespace but preserve internal spaces
    input = strings.TrimSpace(input)
    
    if input == "" {
        fmt.Fprintf(os.Stderr, "Error: Empty input\n")
        os.Exit(1)
    }
    
    // Determine operation
    var output string
    
    if *encodeFlag {
        output = encodeMIMESubject(input)
    } else if *decodeFlag {
        output = decodeMIMESubject(input)
    } else {
        // Auto-detect
        if autoDetect(input) {
            output = decodeMIMESubject(input)
        } else {
            output = encodeMIMESubject(input)
        }
    }
    
    // Write output to stdout with newline at the end
    fmt.Println(output)
}
