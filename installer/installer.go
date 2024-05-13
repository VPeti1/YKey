package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"time"
)

var appName = "YKey"

func clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func installDependencies(distro string) {
	switch distro {
	case "arch":
		exec.Command("sudo", "pacman", "-S", "git", "wget", "go").Run()
	case "debian":
		exec.Command("sudo", "apt-get", "install", "git", "wget", "go").Run()
	case "fedora":
		exec.Command("sudo", "dnf", "install", "git", "wget", "go").Run()
	case "void":
		exec.Command("sudo", "xbps-install", "git", "wget", "go").Run()
	case "opensuse":
		exec.Command("sudo", "zypper", "install", "git", "wget", "go").Run()
	case "skip":
		// Do nothing for skip
	default:
		fmt.Println("Unsupported distribution. Please choose arch, debian, void, opensuse or fedora.")
		dw()
	}
}

func dw() {
	clearScreen()
	var distro string
	fmt.Printf("Enter your Linux distribution (arch/debian/fedora/void/opensuse):\n")
	fmt.Printf("(Derivatives included)\n")
	fmt.Scan(&distro)
	installDependencies(distro)
}

func main() {
	clearScreen()
	fmt.Printf("%s Installer\n", appName)
	fmt.Printf("By VPeti\n")
	time.Sleep(2 * time.Second) // Sleep for 2 seconds
	dw()
	clearScreen()
	fmt.Printf("Press Enter to continue...\n")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	exec.Command("sudo", "rm", "-rf", "/usr/"+appName+"/").Run()
	exec.Command("sudo", "rm", "-rf", "/usr/bin/"+appName).Run()
	exec.Command("sudo", "mkdir", "/usr/"+appName).Run()
	exec.Command("sudo", "git", "clone", "https://github.com/VPeti1/"+appName+".git", "/usr/"+appName).Run()
	exec.Command("sudo", "go", "build", "/usr/"+appName+"/main.go").Run()
	exec.Command("sudo", "cp", "main", "/usr/bin/"+appName).Run()
	exec.Command("sudo", "rm", "-r", "/usr/"+appName+"/").Run()
	fmt.Printf("%s Installer Completed!\n", appName)
}
