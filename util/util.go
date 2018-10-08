package util

import "fmt"

// Display cipher text followed by plain text
func Display(plaintext []byte, ciphertext []byte) {
	i := 0
	j := 0

	if len(plaintext) < 32 {
		for i = 0; i < len(ciphertext); i++ {
			fmt.Printf(" %2x", ciphertext[i])
		}
		fmt.Println()
		for i = 0; i < len(plaintext); i++ {
			fmt.Printf(" %2x", plaintext[i])
		}
		fmt.Println()
		return
	}

	for j = 0; j < len(plaintext)/32; j++ {
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", ciphertext[j*32+i])
		}
		fmt.Print(" :")
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", ciphertext[j*32+16+i])
		}
		fmt.Println()
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", plaintext[j*32+i])
		}
		fmt.Print(" :")
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", plaintext[j*32+16+i])
		}
		fmt.Println()
	}
	remaining := len(plaintext) % 32
	if remaining != 0 {
		for i = 0; i < remaining; i++ {
			fmt.Printf(" %2x", ciphertext[len(ciphertext)-remaining+i])
		}
		fmt.Println()
		for i = 0; i < remaining; i++ {
			fmt.Printf(" %2x", plaintext[len(plaintext)-remaining+i])
		}
		fmt.Println()
	}
}
