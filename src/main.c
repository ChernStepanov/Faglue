#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "structs.h"
#include "validator.h"

uint8_t pe_header[4];
uint32_t header_offset;

const char* format_characteristics(uint32_t characteristics, char *buf, size_t buf_size) {
    if (buf_size == 0) return "";
    buf[0] = '\0';

    size_t current_len = 0;
    int first = 1;

    for (size_t i = 0; i < PE_FLAGS_COUNT; i++) {
        if (characteristics & PE_SECTION_FLAGS[i].mask) {
            int written = snprintf(buf + current_len, buf_size - current_len, 
                                   first ? "%s" : " | %s", PE_SECTION_FLAGS[i].name);
            if (written < 0 || (size_t)written >= buf_size - current_len) {
                break;
            }
            current_len += written;
            first = 0;
        }
    }

    if (first) {
        snprintf(buf, buf_size, "NO_FLAGS");
    }

    return buf;
}

const char* format_permissions(uint32_t characteristics, char perm_str[6]) {
    perm_str[0] = '[';
    perm_str[1] = (characteristics & 0x40000000) ? 'R' : '-';
    perm_str[2] = (characteristics & 0x80000000) ? 'W' : '-';
    perm_str[3] = (characteristics & 0x20000000) ? 'X' : '-';
    perm_str[4] = ']';
    perm_str[5] = '\0';
    return perm_str;
}

void check_headers(FILE* binary, long long file_size){
    char dos_header[2];
    has_dos_header(binary, dos_header);

    fseek(binary, 0x3C, SEEK_SET);
    fread(&header_offset, sizeof(uint32_t), 1, binary);
    check_offset_placement(binary, file_size, header_offset);

    fseek(binary, header_offset, SEEK_SET);
    fread(&pe_header, sizeof(uint8_t), 4, binary);
    is_it_a_PE(binary, pe_header);
    
    if ((uint64_t)header_offset < 0x40) {
        fprintf(stdout, "[WARNING]: PE points inside the DOS header.\n");
    }

}

double calculate_entropy(const uint8_t *sec_data, uint32_t SizeOfRawData) {
    if (SizeOfRawData == 0) return 0.0;
	int buffer[256] = {0};
	unsigned short int c = 0;
	double H = 0;

	for (uint32_t i = 0;i < SizeOfRawData;i++) {
		c = sec_data[i];
		buffer[c]++;
	}
	for (int i = 0;i < 256; i++)
		if (buffer[i] > 0) {
            double p = (double)buffer[i] / SizeOfRawData;
            H -= p * log2(p);
        }
	return H;
}

int main(int argc, char *argv[]){
    if (argc < 2){
        fprintf(stderr, "How can the parser read the file if it doesn't know the name? Add the second argument, please.\n");
        exit(1);
    }

    FILE* binary;
    binary = fopen(argv[1], "rb");
    file_opens(binary);

    long long file_size;
    fseek(binary, 0, SEEK_END);
    file_size = ftell(binary);
    fseek(binary, 0, SEEK_SET);
    is_valid_file(binary, file_size);

    if (file_size < 1024LL){
        fprintf(stdout, "File size: %lld bytes.\n", file_size);
    }
    else if (file_size < 1024LL * 1024){
        fprintf(stdout, "File size: %.2f KB.\n", file_size / 1024.0);
    }
    else if (file_size < 1024LL * 1024 * 1024){
        fprintf(stdout, "File size: %.2f MB.\n", file_size / 1024.0 / 1024.0);
    }
    else {
        fprintf(stdout, "File size: %.2f GB. Pretty large...\n", file_size / 1024.0 / 1024.0 / 1024);
    }

    check_headers(binary, file_size);
    fseek(binary, header_offset + 4, SEEK_SET);

    coff_header file_coff;
    if (fread(&file_coff, sizeof(coff_header), 1, binary) != 1) {
        fprintf(stderr, "Invalid COFF header.\n");
        fclose(binary);
        exit(1);
    }

    int platform = check_platform(file_coff, binary);

    if ((file_coff.SizeOfOptionalHeader != 240 && platform == 0) || (file_coff.SizeOfOptionalHeader != 224 && platform == 1)) {
        fprintf(stdout, "[WARNING]: Anomaly in the optional header's size: %d bytes, not the default size.\n", file_coff.SizeOfOptionalHeader);
    }
    
    fprintf(stdout, "Number of sections: %d\n", file_coff.NumberOfSections);

    long section_table_offset = header_offset + 4 + sizeof(coff_header) + file_coff.SizeOfOptionalHeader;
    fseek(binary, section_table_offset, SEEK_SET);
    

    section_header tsechead;
    uint8_t *sec_data = NULL;

    for (int i = 0;  i < file_coff.NumberOfSections; i++) {
        char flags_buf[512];
        char perms_buf[6];

        fprintf(stdout, "\nSection %d\n", i);
        if (fread(&tsechead, sizeof(section_header), 1, binary) != 1) {
            fprintf(stderr, "Unexpected EOF while reading the section. Exiting immediately.\n");
            break;
        }
        fprintf(stdout, "Name: %.8s\n", tsechead.Name);
        fprintf(stdout, "VirtualSize: %u\n", tsechead.VirtualSize);
        fprintf(stdout, "VirtualAddress: %X\n", tsechead.VirtualAddress);
        fprintf(stdout, "SizeOfRawData: %u\n", tsechead.SizeOfRawData);

        if ((tsechead.SizeOfRawData == 0) && (tsechead.VirtualSize != 0)) {
            fprintf(stdout, "[WARNING]: Empty section. Data may be written in runtime.\n");
        }

        fprintf(stdout, "PointerToRawData: %X\n", tsechead.PointerToRawData);
        fprintf(stdout, "PointerToRelocations: %X\n", tsechead.PointerToRelocations);
        fprintf(stdout, "PointerToLinenumbers: %X\n", tsechead.PointerToLinenumbers);
        fprintf(stdout, "NumberOfRelocations: %u\n", tsechead.NumberOFRelocations);
        fprintf(stdout, "NumberOfLinenumbers: %u\n", tsechead.NumberOfLinenumbers);
        fprintf(stdout, "Characteristics: 0x%08X\n", tsechead.Characteristics);

        format_permissions(tsechead.Characteristics, perms_buf);
        format_characteristics(tsechead.Characteristics, flags_buf, sizeof(flags_buf));

        fprintf(stdout, "Permissions:     %s\n", perms_buf);
        fprintf(stdout, "Flags:    %s\n", flags_buf);

        if ((tsechead.Characteristics & 0x20000000) && (tsechead.Characteristics & 0x80000000)) {
            fprintf(stdout, "[WARNING]: Section has both EXECUTE and WRITE permissions.\n");
        }

        if (tsechead.SizeOfRawData == 0){
            fprintf(stdout, "Section entropy (Shannon): 0\n");
        }
        else {
            long next_header_pos = ftell(binary);
            if ((uint64_t)tsechead.PointerToRawData + (uint64_t)tsechead.SizeOfRawData > (uint64_t)file_size) {
                fprintf(stdout, "Section points outside the file. Kinda weird.\n");
            }
            else {
                fseek(binary, tsechead.PointerToRawData, SEEK_SET);
                sec_data = (uint8_t *)malloc(tsechead.SizeOfRawData);
                if (sec_data == NULL) {
                    fprintf(stderr, "Looks like the section is broken (Error while allocating memory).\n");
                    fseek(binary, next_header_pos, SEEK_SET);
                    continue;
                }
                if (fread(sec_data, sizeof(uint8_t), tsechead.SizeOfRawData, binary) != sizeof(uint8_t)*tsechead.SizeOfRawData) {
                    fprintf(stderr, "Unexpected EOF while reading the section. Exiting immediately.\n");
                    fclose(binary);
                    exit(1);
                }

                double entropy;
                entropy = calculate_entropy(sec_data, tsechead.SizeOfRawData);
                fprintf(stdout, "Section entropy (Shannon): %f\n", entropy);
                if (entropy > 7.0) {
                    fprintf(stdout, "[WARNING]: High section entropy.\n");
                }

                fseek(binary, next_header_pos, SEEK_SET);
                free(sec_data);
            }
        }
        
    }

    fclose(binary);
}
