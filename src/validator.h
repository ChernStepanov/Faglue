#include <stdio.h>
#include <stdlib.h>

void file_opens(FILE* binary) {
    if (binary == NULL){
        fprintf(stderr, "There was some error while trying to access your binary. Please check its' existence and try again.\n");        
        exit(1);
    }
}

void is_valid_file(FILE* binary, long long file_size) {
    if (file_size < 0){
            fprintf(stdout, "Unusual behaviour detected: your OS thinks that the file is smaller than 0 bytes. It's not my fault, so fix it yourself.");
            fclose(binary);
            exit(1);
    }
}

void has_dos_header(FILE* binary, char header[]) {
    if (fread(header, sizeof(char), 2, binary) < 2){
        fprintf(stderr, "I've noticed that the file is WAY too small. Hope you'll pass something less weird the next time.\n");
        exit(1);
    }
    if (memcmp(header, "MZ", 2) != 0){
        fprintf(stderr, "Not a DOS executable (probably the file is corrupted). Quitting.\n");
        exit(1);
    }
}

void check_offset_placement(FILE* binary, long long file_size, uint32_t header_offset) {
    if ((uint64_t)header_offset + 4 > (uint64_t)file_size){
        fprintf(stderr, "The PE offset points outside the file. Some interesting attacks or just a broken binary?... Anyway, static analysis is impossible.\n");
        fclose(binary);
        exit(1);
    }
}

void is_it_a_PE(FILE* binary, uint8_t* header_ptr) {
    if (memcmp(header_ptr, "PE\0\0", 4) != 0){
        fprintf(stderr, "If you see this message, this file looks like a DOS executable, not a PE... I have no desire to work with it.\n");
        fclose(binary);
        exit(1);
    }
}

int check_platform(coff_header file_coff, FILE* binary) {
    if (file_coff.Machine == 0x8664) {
        fprintf(stdout, "Platform: x64\n");
        return 0;
    }
    else if (file_coff.Machine == 0x14c) {
        fprintf(stdout, "Platform: i386 (x32)\n");
        return 1;
    }
    else {
        fprintf(stderr, "This tool is only supposed to work with x32-64 binaries.\n");
        fclose(binary);
        exit(1);
        return 2;
    }
}