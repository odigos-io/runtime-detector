package main

import (
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
	if err == nil {
		defer file1.Close()
	}
	
	// Wait a bit before opening second file
	time.Sleep(500 * time.Millisecond)

	// Open second file
	file2, err := os.Open(file2Path)
	if err == nil {
		defer file2.Close()
	}
	
	// Keep the program running
	time.Sleep(1 * time.Second)
}
