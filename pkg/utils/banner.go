package utils

import "fmt"

func Banner(version string) {
	banner := `                          
      ____  ____ ______________  ______  __
     / __ \/ __ \` + "`" + ` ___/ ___/ _ \/ ___/ |/_/
    / /_/ / /_/ / /  (__  )  __/ /___>  <  
   / .___/\__,_/_/  /____/\___/\___/_/|_|  
  /_/   

v%s - https://github.com/groundsec/parsecx

`
	fmt.Printf(banner, version)
}
