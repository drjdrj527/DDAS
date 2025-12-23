// Detecting duplicate file before it is fully downloaded
// It is getting input of path of folder to scan from the user
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define HASH_SIZE 65
#define CHUNK_SIZE 51200  // 50 KB
#define MAX_FILES 1000    // Adjust based on expected number of files

// SHA-256 implementation constants
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

typedef struct {
    char filepath[1024];    // File path
    char hash[HASH_SIZE];   // Hash of the file
    int exists;             // Flag indicating if the file exists or not
    char original[1024];    // Path of the original file that this file is a duplicate of

} FileStatus;

// Array to track the status of files
static FileStatus file_statuses[MAX_FILES];
static int file_status_count = 0;


uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    // Pad whatever data is left in the buffer.
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    // Copy final state to output
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

void sha256_hash(const char *filename, char outputBuffer[HASH_SIZE]) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Unable to open file for hashing");
        return;
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t buffer[CHUNK_SIZE];
    size_t bytesRead = fread(buffer, 1, CHUNK_SIZE, file);

    sha256_update(&ctx, buffer, bytesRead);
    // if (bytesRead > 0) {
    //     sha256_update(&ctx, buffer, bytesRead);
    // }

    uint8_t hash[32];
    sha256_final(&ctx, hash);

    for (int i = 0; i < 32; ++i) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;

    fclose(file);
}

int is_partial_download(const char *filepath) {
    // Chrome/Edge/Brave
    if (strstr(filepath, ".crdownload")) return 1;
    // Firefox
    if (strstr(filepath, ".part")) return 1;
    // Safari
    if (strstr(filepath, ".download")) return 1;
    // Opera
    if (strstr(filepath, ".opdownload")) return 1;
    
    return 0;
}

int is_hidden(const char *filename) {
    return filename[0] == '.';
}

void sha256_partial_hash(const char *filename, char outputBuffer[HASH_SIZE], size_t chunk_size) {

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Unable to open file for partial hashing");
        return;
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t buffer[chunk_size];
    size_t bytesRead = fread(buffer, 1, chunk_size, file);
    sha256_update(&ctx, buffer, bytesRead);

    uint8_t hash[32];
    sha256_final(&ctx, hash);

    for (int i = 0; i < 32; ++i) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;

    fclose(file);
}

void play_alert_sound(const char *original_path) {
    #ifdef __APPLE__
        system("afplay 'background-error-101soundboards.mp3'");
        char command[2048];
        snprintf(command, sizeof(command), "osascript -e 'display notification \"Duplicate file found: %s\" with title \"Notification\"'", original_path);
        system(command);

    #elif __linux__
        system("aplay 'background-error-101soundboards.mp3' || mpg123 'background-error-101soundboards.mp3'");
        char command[2048];
        snprintf(command, sizeof(command), "notify-send 'Notification' 'Duplicate file found: %s'", original_path);
        system(command);

    #else
        printf("Unsupported OS for sound playback\n");
    #endif
}
int file_already_alerted(const char *filepath, char alerted_partial_files[MAX_FILES][1024], int *alerted_partial_count) {
    for (int i = 0; i < *alerted_partial_count; ++i) {
        if (strcmp(alerted_partial_files[i], filepath) == 0) {
            return 1;  // File has already triggered an alert
        }
    }
    return 0;  // File has not triggered an alert yet
}

void monitor_directory_with_alerts(const char *path, FILE *full_hash_file, FILE *partial_hash_file,
                                   char full_seen_hashes[MAX_FILES][HASH_SIZE], int *full_seen_count,
                                   char partial_seen_hashes[MAX_FILES][HASH_SIZE], int *partial_seen_count,
                                   char processed_files[MAX_FILES][1024], int *processed_count,
                                   char alerted_partial_files[MAX_FILES][1024], int *alerted_partial_count) {
    struct dirent *entry;
    DIR *dp = opendir(path);
    if (!dp) {
        perror("Unable to open directory for monitoring");
        return;
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char new_path[1024];
            snprintf(new_path, sizeof(new_path), "%s/%s", path, entry->d_name);
            monitor_directory_with_alerts(new_path, full_hash_file, partial_hash_file, 
                                          full_seen_hashes, full_seen_count, 
                                          partial_seen_hashes, partial_seen_count, 
                                          processed_files, processed_count, 
                                          alerted_partial_files, alerted_partial_count);  // Recursively scan subdirectories
        } else if (entry->d_type == DT_REG) {
            if (is_hidden(entry->d_name)) {
                continue;  // Skip hidden files
            }

            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

            // Check if this file has already been processed
            int already_processed = 0;
            for (int i = 0; i < *processed_count; ++i) {
                if (strcmp(processed_files[i], filepath) == 0) {
                    already_processed = 1;
                    break;
                }
            }

            if (already_processed) {
                continue;  // Skip already processed files
            }

            int is_partial_file = is_partial_download(filepath);
            char hash[HASH_SIZE];

            if (is_partial_file) {
                // Compute partial hash for files with extensions like .crdownload, .part, etc.
                sha256_partial_hash(filepath, hash, CHUNK_SIZE);

                int duplicate_found = 0;
                // Check against fully downloaded files only
                for (int i = 0; i < *full_seen_count; ++i) {
                    if (strcmp(full_seen_hashes[i], hash) == 0) {
                        duplicate_found = 1;
                        printf("Alert: Duplicate found for partially downloading file!\nFile: %s\n", filepath);
                        play_alert_sound(file_statuses[i].filepath);  // Pass the original file's path
                        if (*alerted_partial_count < MAX_FILES) {
                            // Track the partial file alert
                            strcpy(alerted_partial_files[*alerted_partial_count], filepath);
                            (*alerted_partial_count)++;
                        }
                        break;
                    }
                }

                // If no duplicate found, store the hash but do not alert
                if (!duplicate_found) {
                    if (*partial_seen_count < MAX_FILES) {
                        strcpy(partial_seen_hashes[*partial_seen_count], hash);
                        (*partial_seen_count)++;
                    }
                    fprintf(partial_hash_file, "%s %s\n", hash, filepath);
                    fflush(partial_hash_file);  // Ensure the hash is written immediately
                }

            } else {
                // For fully downloaded files, compute full hash
                sha256_hash(filepath, hash);

                // Check for duplicates among fully downloaded files
                int duplicate_found = 0;
                for (int i = 0; i < *full_seen_count; ++i) {
                    if (strcmp(full_seen_hashes[i], hash) == 0) {
                        duplicate_found = 1;
                        printf("Alert: Duplicate found!\nFile: %s\n", filepath);
                        play_alert_sound(file_statuses[i].filepath);  // Pass the original file's path
                        strcpy(file_statuses[file_statuses[i].exists].original, file_statuses[i].filepath);
                        break;
                    }
                }

                if (!duplicate_found) {
                    if (*full_seen_count < MAX_FILES) {
                        strcpy(full_seen_hashes[*full_seen_count], hash);
                        strcpy(file_statuses[*full_seen_count].filepath, filepath);
                        file_statuses[*full_seen_count].exists = 1;  // Mark as exists
                        strcpy(file_statuses[*full_seen_count].hash, hash);
                        (*full_seen_count)++;
                    }
                    fprintf(full_hash_file, "%s %s\n", hash, filepath);
                    fflush(full_hash_file);  // Ensure the hash is written immediately
                }
            }

            // Record this file as processed
            if (*processed_count < MAX_FILES) {
                strcpy(processed_files[*processed_count], filepath);
                (*processed_count)++;
            }
        }
    }

    closedir(dp);
}

// Add code to remove the .crdownload file after processing
void handle_crdownload_files(const char *path, FILE *hash_file, char seen_hashes[MAX_FILES][HASH_SIZE], int *seen_count) {
    struct dirent *entry;
    DIR *dp = opendir(path);
    if (!dp) {
        perror("Unable to open directory for monitoring");
        return;
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) {
            if (strstr(entry->d_name, ".crdownload")) {
                char filepath[1024];
                snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

                char hash[HASH_SIZE];
                sha256_hash(filepath, hash);

                int duplicate_found = 0;
                for (int i = 0; i < *seen_count; ++i) {
                    if (strcmp(seen_hashes[i], hash) == 0) {
                        duplicate_found = 1;
                        printf("Now duplicate file is being downloaded!\nFile: %s\n", filepath);
                        // play_alert_sound();
                        break;
                    }
                }

                if (!duplicate_found) {
                    if (*seen_count < MAX_FILES) {
                        strcpy(seen_hashes[*seen_count], hash);
                        (*seen_count)++;
                    }
                }

                // Remove the .crdownload file if it's no longer needed
                remove(filepath);
            }
        }
    }
    closedir(dp);
}

int main() {
    char directory_path[256];

    // Prompt the user for the directory path
    printf("Enter directory path to scan: ");
    if (fgets(directory_path, sizeof(directory_path), stdin) == NULL) {
        perror("fgets");
        return EXIT_FAILURE;
    }

    // Remove the newline character from the input
    directory_path[strcspn(directory_path, "\n")] = '\0';

    // Print the directory path to verify input
    printf("Directory path: %s\n", directory_path);

    // Create fresh new files for storing hashes of fully and partially downloaded files
    FILE *full_hash_file = fopen("full_download_files.txt", "w");
    if (!full_hash_file) {
        perror("Unable to open file for writing full download hashes");
        return 1;
    }
    fclose(full_hash_file);  // Close the file after creating it

    FILE *partial_hash_file = fopen("partial_download_files.txt", "w");
    if (!partial_hash_file) {
        perror("Unable to open file for writing partial download hashes");
        return 1;
    }
    fclose(partial_hash_file);  // Close the file after creating it

    // Arrays to store the hashes of fully and partially downloaded files
    static char full_seen_hashes[MAX_FILES][HASH_SIZE];
    static int full_seen_count = 0;

    static char partial_seen_hashes[MAX_FILES][HASH_SIZE];
    static int partial_seen_count = 0;

    // Array to store paths of already processed files
    static char processed_files[MAX_FILES][1024];
    static int processed_count = 0;

    // Array to track files that have already triggered an alert for partial download
    static char alerted_partial_files[MAX_FILES][1024];
    static int alerted_partial_count = 0;

    while (1) {
        // Open the hash files in append mode to update them with newly detected file hashes
        full_hash_file = fopen("full_download_files.txt", "a");
        if (!full_hash_file) {
            perror("Unable to open file for appending full download hashes");
            return 1;
        }

        partial_hash_file = fopen("partial_download_files.txt", "a");
        if (!partial_hash_file) {
            perror("Unable to open file for appending partial download hashes");
            return 1;
        }

        // Call the directory monitoring function to check the directory for new downloads
        // and update the hash arrays accordingly.
        monitor_directory_with_alerts(directory_path, full_hash_file, partial_hash_file,
                                      full_seen_hashes, &full_seen_count,
                                      partial_seen_hashes, &partial_seen_count,
                                      processed_files, &processed_count,
                                      alerted_partial_files, &alerted_partial_count);

        // Close the hash files after each scan iteration to ensure data is saved
        fclose(full_hash_file);
        fclose(partial_hash_file);

        // Sleep for a short duration (1 second) before scanning again
        sleep(1);
    }
    return 0;
}
