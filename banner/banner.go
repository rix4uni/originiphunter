package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.0.4"

func PrintVersion() {
	fmt.Printf("Current originiphunter version %s\n", version)
}

// Prints the Colorful banner
func PrintBanner() {
	banner := `
                _         _         _         __                   __             
  ____   _____ (_)____ _ (_)____   (_)____   / /_   __  __ ____   / /_ ___   _____
 / __ \ / ___// // __  // // __ \ / // __ \ / __ \ / / / // __ \ / __// _ \ / ___/
/ /_/ // /   / // /_/ // // / / // // /_/ // / / // /_/ // / / // /_ /  __// /    
\____//_/   /_/ \__, //_//_/ /_//_// .___//_/ /_/ \__,_//_/ /_/ \__/ \___//_/     
               /____/             /_/
`
    fmt.Printf("%s\n%65s\n\n", banner, "Current originiphunter version "+version)
}
