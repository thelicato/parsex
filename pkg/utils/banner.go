package utils

import "fmt"

func Banner(version string) {
	banner := `                          
░▀█▀░█░█░█▀▀░█░░░▀█▀░█▀▀░█▀█░▀█▀░█▀█
░░█░░█▀█░█▀▀░█░░░░█░░█░░░█▀█░░█░░█░█
░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░░▀░░▀▀▀

v%s - https://github.com/thelicato/parsex

`
	fmt.Printf(banner, version)
}
