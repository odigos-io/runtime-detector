package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	// Get the file paths from command line arguments
	if len(os.Args) != 3 {
		panic("usage: ./multi_file_test <file1_path> <file2_path>")
	}
	file1Path := os.Args[1]
	file2Path := os.Args[2]

	time.Sleep(1 * time.Second)

	// Open first file
	file1, err := os.Open(file1Path)
	if err != nil {
		fmt.Printf("Error opening first file: %v\n", err)
		os.Exit(1)
	}
	defer file1.Close()

	// Ensure the file is actually opened by reading from it
	buf := make([]byte, 4)
	_, _ = file1.Read(buf)

	// Wait a bit before opening second file
	time.Sleep(500 * time.Millisecond)

	// Open second file
	file2, err := os.Open(file2Path)
	if err != nil {
		fmt.Printf("Error opening second file: %v\n", err)
		os.Exit(1)
	}
	defer file2.Close()

	// Ensure the file is actually opened by reading from it
	_, _ = file2.Read(buf)
	// Keep the program running
	time.Sleep(1 * time.Second)
	fmt.Println("Files opened successfully")
}
