package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)
// --- Signature and Version Information ---
const toolVersion = "v1.1"
const toolAuthor = "Built by Dharan - github.com/Dharan10"
// ----------------------------------------

// STRUCT DEFINITION MUST BE HERE TO BE GLOBALLY RECOGNIZED
type WardenProcess struct {
	PID        int32
	PPID       int32
	Name       string
	Executable string
	CreateTime string
}

var (
	listFlag  = flag.Bool("list", false, "List all running processes (PID, PPID, User, Command).")
	iocFlag   = flag.Bool("ioc", false, "Perform Binary String Analysis (IOC Hunting) on the PID's executable.")
	killFlag  = flag.Bool("kill", false, "DANGER: Terminate the PID and its entire process tree (Recursive Kill).")
	cleanFlag = flag.Bool("clean", false, "Perform Attacker Clean-Up Audit (Deleted File Check).")
	targetPID int32
)

func printUsage() {
	// CORRECTED: Print the version and author strings directly.
	fmt.Fprintf(os.Stderr, "Warden - Host-Based Forensic Triage Utility (%s)\n", toolVersion)
	fmt.Fprintf(os.Stderr, "%s\n\n", toolAuthor) 

	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  ./warden --list                            # Mode 1: LIST all running processes.\n")
	fmt.Fprintf(os.Stderr, "  ./warden <PID>                             # Mode 2: INSPECT a specific process (default).\n")
	fmt.Fprintf(os.Stderr, "  ./warden --ioc <PID>                       # Mode 3: BINARY IOC Hunting.\n")
	fmt.Fprintf(os.Stderr, "  ./warden --kill <PID>                      # Mode 4: ACTIVE RESPONSE (Terminate Process Tree).\n")
	fmt.Fprintf(os.Stderr, "  ./warden --clean <PID>                     # Mode 5: CLEAN-UP AUDIT (Deleted File Check).\n")
	fmt.Fprintf(os.Stderr, "  ./warden -h | --help                       # Show this help message.\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func parsePID() bool {
	args := flag.Args()
	if len(args) == 0 {
		return false
	}
	pid, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid PID '%s'. Must be a valid process number.\n", args[0])
		os.Exit(1)
	}
	targetPID = int32(pid)
	return true
}

func main() {
	flag.Parse()

	if !*listFlag && !*iocFlag && !*killFlag && !*cleanFlag && flag.NFlag() == 0 && flag.NArg() == 0 {
		printUsage()
		return
	}

	if *listFlag {
		listRunningProcesses()
		return
	}

	if !parsePID() {
		if *iocFlag || *killFlag || *cleanFlag {
			fmt.Fprintf(os.Stderr, "Error: A PID must be provided for this mode.\n")
			os.Exit(1)
		}
	}

	if *killFlag {
		terminateProcessTree(targetPID)
	} else if *cleanFlag {
		cleanUpAudit(targetPID)
	} else if *iocFlag {
		inspectProcess(targetPID)
		binaryStringAnalysis(targetPID)
	} else if flag.NArg() > 0 && flag.NFlag() == 0 {
		inspectProcess(targetPID)
	}
}

func listRunningProcesses() {
	processes, err := process.Processes()
	if err != nil {
		fmt.Printf("ERROR: Could not list processes: %v. Requires elevated permissions on some systems.\n", err)
		return
	}

	fmt.Println("--- WARDEN PROCESS LIST (Triage View) ---")
	fmt.Printf("%-8s | %-8s | %-20s | %-30s\n", "PID", "PPID", "USER", "COMMAND")
	fmt.Println(strings.Repeat("-", 70))

	for _, p := range processes {
		ppid, _ := p.Ppid()
		username, _ := p.Username()
		name, _ := p.Name()

		if len(name) > 28 {
			name = name[:25] + "..."
		}
		fmt.Printf("%-8d | %-8d | %-20s | %-30s\n", p.Pid, ppid, username, name)
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("Run 'warden <PID>' for detailed forensic inspection.")
}

func inspectProcess(targetPID int32) {
	fmt.Printf("\n--- WARDEN FORENSIC INSPECTION: PID %d ---\n", targetPID)

	targetProc, err := process.NewProcess(targetPID)
	if err != nil {
		fmt.Printf("[!] Error retrieving process details for PID %d: %v\n", targetPID, err)
		return
	}

	fmt.Println(">> 1. PROCESS LINEAGE (Execution History)")
	lineage := getProcessLineage(targetPID)
	if len(lineage) == 0 {
		fmt.Println("   [!] Lineage trace failed.")
	}
	for i := len(lineage) - 1; i >= 0; i-- {
		p := lineage[i]
		arrow := " └──> "
		if i == 0 {
			arrow = " ROOT: "
		}
		fmt.Printf("   %s PID: %d | PPID: %d | Start: %s | Cmd: %s\n",
			arrow, p.PID, p.PPID, p.CreateTime, p.Name)
	}

	fmt.Println("\n>> 2. EXECUTABLE INTEGRITY CHECK")
	execPath, _ := targetProc.Exe()
	hash := getFileSHA256(execPath)
	fmt.Printf("   Executable Path: %s\n", execPath)
	fmt.Printf("   SHA256 Hash:     %s\n", hash)
	if strings.Contains(strings.ToUpper(execPath), "TEMP") {
		fmt.Println("   [WARNING] Executing from a temporary path is often suspicious.")
	}

	fmt.Println("\n>> 3. RESOURCE & NETWORK ACTIVITY")
	
	openFiles, _ := targetProc.OpenFiles()
	fmt.Printf("   Open Files Count: %d\n", len(openFiles))
	if len(openFiles) > 100 {
		fmt.Println("   [ALERT] High file count is suspicious (may indicate disk scanning).")
	}

	connections, _ := targetProc.Connections()
	fmt.Printf("   Network Connections: %d active\n", len(connections))
	for _, conn := range connections {
		if conn.Status == "LISTEN" || conn.Status == "ESTABLISHED" {
			fmt.Printf("     - %s:%d -> %s:%d (%s)\n", 
				conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status)
		}
	}
}

func binaryStringAnalysis(targetPID int32) {
	targetProc, err := process.NewProcess(targetPID)
	if err != nil {
		fmt.Printf("[!] Cannot perform IOC analysis: %v\n", err)
		return
	}
	execPath, _ := targetProc.Exe()

	fmt.Println("\n>> 4. BINARY STRING ANALYSIS (IOC Hunting)")
	strings := extractASCIISuspiciousStrings(execPath)
	
	if len(strings) == 0 {
		fmt.Println("   [INFO] No suspicious strings found in the binary file.")
	} else {
		fmt.Printf("   [ALERT] Found %d potential Indicators of Compromise (IOCs):\n", len(strings))
		for _, s := range strings {
			fmt.Printf("     - %s\n", s)
		}
	}
}

func cleanUpAudit(targetPID int32) {
	fmt.Printf("\n--- WARDEN CLEAN-UP AUDIT: PID %d ---\n", targetPID)

	targetProc, err := process.NewProcess(targetPID)
	if err != nil {
		fmt.Printf("[!] Cannot perform clean-up audit: %v\n", err)
		return
	}
	execPath, _ := targetProc.Exe()

	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		fmt.Printf(">> 1. EXECUTABLE STATUS: CRITICAL - File Not Found (Ephemeral Binary) 🚨\n")
		fmt.Printf("   The executable binary is missing from disk: %s\n", execPath)
		fmt.Println("   [ACTION] This suggests self-deletion to evade forensic recovery.")
	} else {
		fmt.Println(">> 1. EXECUTABLE STATUS: CLEAN - File exists on disk.")
	}

	fmt.Println("\n>> 2. LINEAGE DELETION AUDIT")
	lineage := getProcessLineage(targetPID)
	foundCleanUp := false

	suspiciousCmds := []string{"rm -rf", "shred", "history -c", "vssadmin delete", "cipher /w", "del *.log", "erase *"}

	for _, p := range lineage {
		cmd := strings.ToLower(p.Name)
		for _, susCmd := range suspiciousCmds {
			if strings.Contains(cmd, strings.ToLower(susCmd)) {
				fmt.Printf("   [ALERT] PID %d (%s) ran suspicious command: %s\n", p.PID, p.Name, p.CreateTime)
				foundCleanUp = true
			}
		}
	}

	if !foundCleanUp {
		fmt.Println("   [INFO] No known attacker clean-up commands detected in the process lineage.")
	}
}

func terminateProcessTree(targetPID int32) {
	fmt.Printf("\n--- WARDEN ACTIVE RESPONSE: TERMINATION ---")
	fmt.Printf("\n[DANGER] Attempting to terminate PID %d and all its descendants...\n", targetPID)

	children, err := getDescendantPIDs(targetPID)
	if err != nil {
		fmt.Printf("[ERROR] Could not enumerate process tree for termination: %v\n", err)
		return
	}

	pidsToKill := append(children, targetPID)

	killedCount := 0
	for i := len(pidsToKill) - 1; i >= 0; i-- {
		pid := pidsToKill[i]
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		if err := p.Kill(); err != nil {
			if strings.Contains(err.Error(), "operation not permitted") {
				if killErr := syscall.Kill(int(pid), syscall.SIGKILL); killErr == nil {
					killedCount++
					fmt.Printf("[SUCCESS] Forced SIGKILL on PID %d\n", pid)
					continue
				}
			}
			fmt.Printf("[ERROR] Failed to kill PID %d: %v\n", pid, err)
		} else {
			killedCount++
			fmt.Printf("[SUCCESS] Terminated PID %d\n", pid)
		}
	}

	fmt.Printf("\n[SUMMARY] Successfully terminated %d processes in the tree.\n", killedCount)
	fmt.Printf("Re-run 'warden %d' to verify termination status.\n", targetPID)
}

func getDescendantPIDs(pid int32) ([]int32, error) {
	var descendants []int32
	
	p, err := process.NewProcess(pid)
	if err != nil {
		return nil, err
	}

	children, err := p.Children()
	if err != nil {
		return nil, nil
	}

	for _, child := range children {
		descendants = append(descendants, child.Pid)
		grandDescendants, _ := getDescendantPIDs(child.Pid)
		descendants = append(descendants, grandDescendants...)
	}

	return descendants, nil
}

func extractASCIISuspiciousStrings(filePath string) []string {
	const minStringLen = 6
	
	file, err := os.Open(filePath)
	if err != nil {
		return []string{fmt.Sprintf("ERROR: Cannot open executable for string analysis: %v", err)}
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return []string{fmt.Sprintf("ERROR: Cannot read content: %v", err)}
	}

	var suspiciousStrings []string
	var currentString []byte

	iocPatterns := []string{
		"http://", "https://", ".ru/", ".top", 
		"powershell", "cmd.exe", "wmic", 
		"C:\\Users", "/etc/", "tmp/", 
		".key", "password", "secret", 
	}

	for _, b := range content {
		if b >= 32 && b <= 126 {
			currentString = append(currentString, b)
		} else {
			if len(currentString) >= minStringLen {
				s := string(currentString)
				for _, pattern := range iocPatterns {
					if strings.Contains(strings.ToLower(s), strings.ToLower(pattern)) {
						suspiciousStrings = append(suspiciousStrings, s)
						break
					}
				}
			}
			currentString = nil
		}
	}
	
	if len(currentString) >= minStringLen {
		s := string(currentString)
		for _, pattern := range iocPatterns {
			if strings.Contains(strings.ToLower(s), strings.ToLower(pattern)) {
				suspiciousStrings = append(suspiciousStrings, s)
				break
			}
		}
	}

	uniqueStrings := make(map[string]bool)
	var result []string
	for _, s := range suspiciousStrings {
		if _, ok := uniqueStrings[s]; !ok {
			uniqueStrings[s] = true
			result = append(result, s)
		}
	}

	return result
}

func getProcessLineage(pid int32) []WardenProcess {
	var lineage []WardenProcess
	currentPID := pid

	for {
		p, err := process.NewProcess(currentPID)
		if err != nil {
			break
		}

		ppid, _ := p.Ppid()
		createTime, _ := p.CreateTime()
		cmdLine, _ := p.Cmdline()
		name, _ := p.Name()

		displayCmd := name
		if cmdLine != "" {
			displayCmd = cmdLine
		}
		if len(displayCmd) > 50 {
			displayCmd = displayCmd[:47] + "..."
		}

		lineage = append(lineage, WardenProcess{
			PID: currentPID,
			PPID: ppid,
			Name: displayCmd,
			CreateTime: time.UnixMilli(createTime).Format("15:04:05 Jan 2"),
		})

		if currentPID == 1 || ppid == 0 || ppid == currentPID {
			break
		}
		currentPID = ppid
	}
	return lineage
}

func getFileSHA256(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Sprintf("N/A (Error opening file: %v)", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Sprintf("N/A (Error reading file: %v)", err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}
