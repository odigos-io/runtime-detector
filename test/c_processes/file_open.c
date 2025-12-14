#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    FILE *file1 = NULL;
    FILE *file2 = NULL;
    char buf[4];
    
    // Check command line arguments
    if (argc != 3) {
        fprintf(stderr, "usage: %s <file1> <file2>\n", argv[0]);
        return 1;
    }
    
    char *file1Path = argv[1];
    char *file2Path = argv[2];
    
    // using sleep for testing purposes to space out the events we look for
    sleep(1);
    
    file1 = fopen(file1Path, "r");
    if (file1 == NULL) {
        fprintf(stderr, "Error opening first file: %s\n", file1Path);
        return 1;
    }
    
    // Ensure the file is actually opened by reading from it
    fread(buf, 1, 4, file1);
    
    // Wait before opening second file
    sleep(1);
    
    file2 = fopen(file2Path, "r");
    if (file2 == NULL) {
        fprintf(stderr, "Error opening second file: %s\n", file2Path);
        fclose(file1);
        return 1;
    }
    
    // Ensure the file is actually opened by reading from it
    fread(buf, 1, 4, file2);
    
    sleep(1);
    
    printf("Files opened successfully\n");
    
    fclose(file1);
    fclose(file2);
    
    return 0;
}