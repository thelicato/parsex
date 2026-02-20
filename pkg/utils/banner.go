package utils

import "fmt"

func Banner(version string) {
	banner := `                          
░▀█▀░█░█░█▀▀░█░░░▀█▀░█▀▀░█▀█░▀█▀░█▀█
░░█░░█▀█░█▀▀░█░░░░█░░█░░░█▀█░░█░░█░█
░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░░▀░░▀▀▀

v%s - https://github.com/thelicato/parsecx

`
	fmt.Printf(banner, version)
}
