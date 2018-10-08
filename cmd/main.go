package main

import (
	"fmt"

	"github.com/srinivengala/cryptmt/ecrypt"
)

func main() {

	fmt.Println("Key sizes in bytes:", ecrypt.GetKeySizesString(", "))

}
