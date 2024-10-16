package main

import (
    "bufio"
    "flag"
    "fmt"
    "log"
    "os"
    "os/exec"
)

func main() {
    // Parsing command-line flags
    domainsFile := flag.String("d", "", "Path to domains file")
    subdomainsFile := flag.String("s", "subdomains.txt", "Optional: Output file for live subdomains")
    fuzz2File := flag.String("f", "", "Path to FUZZ2 wordlist for ffuf")
    outputFile := flag.String("o", "", "Optional: Output file for final results (if not set, results will be printed to stdout)")
    flag.Parse()

    if *domainsFile == "" || *fuzz2File == "" {
        log.Fatal("Usage: -d <domains file> -f <fuzz2 wordlist> [-s <subdomains output file>] [-o <output file>]")
    }

    // Step 1: Run Subfinder on each domain from the domains file
    subdomains := findSubdomains(*domainsFile)

    // Step 2: Probe subdomains with httpx to check if they are live
    liveSubdomains := probeSubdomains(subdomains, *subdomainsFile)

    // Step 3: Pass the live subdomains to FFUF with FUZZ2 for clusterbomb fuzzing
    err := runFfuf(liveSubdomains, *fuzz2File, *outputFile)
    if err != nil {
        log.Fatal("Error running ffuf: ", err)
    }
}

// Function to run Subfinder and generate a subdomains list
func findSubdomains(domainsFile string) []string {
    file, err := os.Open(domainsFile)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    subdomains := []string{}
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domain := scanner.Text()
        fmt.Println("Running subfinder for domain:", domain)

        // Run subfinder command
        cmd := exec.Command("subfinder", "-d", domain)
        output, err := cmd.Output()
        if err != nil {
            log.Fatal("Subfinder command failed: ", err)
        }

        // Append output results to subdomains slice
        subdomains = append(subdomains, string(output))
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    return subdomains
}

// Updated Function to probe subdomains with httpx and filter live ones
func probeSubdomains(subdomains []string, subdomainsFile string) []string {
    liveSubdomains := []string{}

    // Save subdomains to a temporary file for httpx input
    tmpFile, err := os.CreateTemp("", "httpx-input-")
    if err != nil {
        log.Fatal(err)
    }
    defer os.Remove(tmpFile.Name())

    writer := bufio.NewWriter(tmpFile)
    for _, subdomain := range subdomains {
        fmt.Fprintln(writer, subdomain)
    }
    writer.Flush()
    tmpFile.Close()

    // Run httpx to probe live subdomains
    cmd := exec.Command("httpx", "-l", tmpFile.Name(), "-o", tmpFile.Name()+"-live")
    err = cmd.Run()
    if err != nil {
        log.Fatal("httpx command failed: ", err)
    }

    // Read live subdomains
    liveFile, err := os.Open(tmpFile.Name() + "-live")
    if err != nil {
        log.Fatal(err)
    }
    defer liveFile.Close()

    scanner := bufio.NewScanner(liveFile)
    for scanner.Scan() {
        liveSubdomains = append(liveSubdomains, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    // If -s flag is provided, write live subdomains to the output file
    if subdomainsFile != "" {
        outFile, err := os.Create(subdomainsFile)
        if err != nil {
            log.Fatal("Error creating subdomains file: ", err)
        }
        defer outFile.Close()

        outWriter := bufio.NewWriter(outFile)
        for _, liveSubdomain := range liveSubdomains {
            fmt.Fprintln(outWriter, liveSubdomain)
        }
        outWriter.Flush()
    }

    return liveSubdomains
}

// Function to run FFUF with live subdomains as FUZZ1 and a given FUZZ2 wordlist
func runFfuf(subdomains []string, fuzz2File, outputFile string) error {
    // Save live subdomains to a temporary file for FUZZ1
    tmpFile, err := os.CreateTemp("", "fuzz1-")
    if err != nil {
        return err
    }
    defer os.Remove(tmpFile.Name())

    writer := bufio.NewWriter(tmpFile)
    for _, subdomain := range subdomains {
        fmt.Fprintln(writer, subdomain)
    }
    writer.Flush()
    tmpFile.Close()

    // Build ffuf command
    ffufCmd := exec.Command("ffuf", "-w", tmpFile.Name()+":FUZZ1", "-w", fuzz2File+":FUZZ2", "-u", "https://FUZZ1FUZZ2", "-mode", "clusterbomb", "-mc", "200,403", "-c")

    // If an output file is specified, write results to that file
    if outputFile != "" {
        ffufCmd.Args = append(ffufCmd.Args, "-o", outputFile)
    }

    // Set output to stdout if no file is provided
    ffufCmd.Stdout = os.Stdout
    ffufCmd.Stderr = os.Stderr

    fmt.Println("Running ffuf clusterbomb fuzzing...")
    return ffufCmd.Run()
}
