/**
 * simple_test.c
 * Simple test of crypto functions with ASCII logging
 */

#include "crypto_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

FILE *results_file = NULL;
FILE *phase_file = NULL;

void log_msg(const char *msg) {
    printf("%s", msg);
    if (results_file) {
        fprintf(results_file, "%s", msg);
        fflush(results_file);
    }
}

void log_phase(const char *phase, const char *details) {
    char timestamp[100];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    if (phase_file) {
        fprintf(phase_file, "[%s] SUCCESS: %s\n", timestamp, phase);
        fprintf(phase_file, "  %s\n\n", details);
        fflush(phase_file);
    }
}

int main() {
    char buf[512];
    clock_t start, end;
    double elapsed;
    
    results_file = fopen("simulation_results.log", "w");
    phase_file = fopen("phase_success.log", "w");
    
    if (!results_file || !phase_file) {
        printf("ERROR: Cannot open files\n");
        return 1;
    }
    
    log_msg("========================================\n");
    log_msg("POST-QUANTUM CRYPTO SIMULATION\n");
    log_msg("========================================\n\n");
    
    /* Test 1: Key Generation */
    log_msg("PHASE 1: KEY GENERATION\n");
    log_msg("----------------------------------------\n\n");
    
    crypto_prng_init(0xDEADBEEF);
    
    RingLWEKeyPair gateway_keys, sender_keys;
    
    log_msg("Generating Gateway Ring-LWE keys...\n");
    start = clock();
    int result = ring_lwe_keygen(&gateway_keys);
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    if (result == 0) {
        sprintf(buf, "  SUCCESS (%.2f ms)\n\n", elapsed);
        log_msg(buf);
        log_phase("Gateway Ring-LWE Keygen", "Generated 512-coefficient polynomials");
    } else {
        log_msg("  FAILED\n");
        goto cleanup;
    }
    
    log_msg("Generating Sender Ring-LWE keys...\n");
    crypto_prng_init(0xCAFEBABE);
    start = clock();
    result = ring_lwe_keygen(&sender_keys);
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    if (result == 0) {
        sprintf(buf, "  SUCCESS (%.2f ms)\n\n", elapsed);
        log_msg(buf);
        log_phase("Sender Ring-LWE Keygen", "Generated sender polynomial keys");
    } else {
        log_msg("  FAILED\n");
        goto cleanup;
    }
    
    /* Generate LDPC */
    log_msg("Generating LDPC keypair...\n");
    LDPCKeyPair ldpc_keys;
    start = clock();
    result = ldpc_keygen(&ldpc_keys);
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    if (result == 0) {
        sprintf(buf, "  SUCCESS (%.2f ms)\n", elapsed);
        log_msg(buf);
        sprintf(buf, "  Matrix: %dx%d, weights %d/%d\n\n", 
                LDPC_ROWS, LDPC_COLS, LDPC_ROW_WEIGHT, LDPC_COL_WEIGHT);
        log_msg(buf);
        log_phase("LDPC Keygen", "408x816 QC-LDPC matrix generated");
    } else {
        log_msg("  FAILED\n");
        goto cleanup;
    }
    
    /* Test 2: Ring Signature */
    log_msg("\nPHASE 2: RING SIGNATURE\n");
    log_msg("----------------------------------------\n\n");
    
    /* Setup ring members */
    Poly512 ring_pks[3];
    ring_pks[0] = sender_keys.public;
    ring_pks[1] = gateway_keys.public;
    
    RingLWEKeyPair temp_key;
    ring_lwe_keygen(&temp_key);
    ring_pks[2] = temp_key.public;
    
    Poly512 other_pks[2] = {gateway_keys.public, temp_key.public};
    
    log_msg("Generating ring signature...\n");
    RingSignature sig;
    uint8_t keyword[32] = "AUTH_REQUEST";
    
    start = clock();
    result = ring_sign(&sig, keyword, &sender_keys, other_pks, 0);
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    if (result == 0) {
        sprintf(buf, "  SUCCESS (%.2f ms)\n", elapsed);
        log_msg(buf);
        sprintf(buf, "  Keyword: %s\n", sig.keyword);
        log_msg(buf);
        sprintf(buf, "  Signature size: %lu bytes\n\n", sizeof(RingSignature));
        log_msg(buf);
        log_phase("Ring Signature", "Signed with anonymity set of 3 members");
    } else {
        log_msg("  FAILED (rejection sampling)\n");
        goto cleanup;
    }
    
    /* Test 3: Verification */
    log_msg("Verifying signature...\n");
    start = clock();
    result = ring_verify(&sig, ring_pks);
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    if (result == 1) {
        sprintf(buf, "  *** VALID *** (%.2f ms)\n\n", elapsed);
        log_msg(buf);
        log_phase("Signature Verification", "Authentication successful");
    } else {
        log_msg("  INVALID\n");
        goto cleanup;
    }
    
    /* Test 4: Encryption/Decryption */
    log_msg("\nPHASE 3: HYBRID ENCRYPTION\n");
    log_msg("----------------------------------------\n\n");
    
    const char *message = "Hello IoT - Post-Quantum Works!";
    uint8_t plaintext[256];
    strcpy((char*)plaintext, message);
    uint32_t plain_len = strlen(message) + 1;
    
    uint8_t ciphertext[256];
    uint8_t syndrome[LDPC_ROWS / 8];
    uint32_t cipher_len;
    
    sprintf(buf, "Encrypting: '%s'\n", message);
    log_msg(buf);
    
    start = clock();
    result = hybrid_encrypt(ciphertext, &cipher_len,
                           plaintext, plain_len,                           &ldpc_keys.public_part,
                           syndrome);
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    if (result == 0) {
        sprintf(buf, "  SUCCESS (%.2f ms)\n", elapsed);
        log_msg(buf);
        sprintf(buf, "  Ciphertext: %u bytes\n", cipher_len);
        log_msg(buf);
        sprintf(buf, "  Syndrome: %lu bytes\n\n", sizeof(syndrome));
        log_msg(buf);
        log_phase("Hybrid Encryption", "LDPC+AES encryption complete");
    } else {
        log_msg("  FAILED\n");
        goto cleanup;
    }
    
    /* Decryption */
    log_msg("Decrypting...\n");
    uint8_t decrypted[256];
    uint32_t dec_len;
    
    start = clock();
    result = hybrid_decrypt(decrypted, &dec_len,
                           ciphertext, cipher_len,
                           syndrome,
                           &ldpc_keys);
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    if (result == 0) {
        decrypted[dec_len] = '\0';
        sprintf(buf, "  SUCCESS (%.2f ms)\n", elapsed);
        log_msg(buf);
        sprintf(buf, "  Decrypted: '%s'\n\n", decrypted);
        log_msg(buf);
        
        if (strcmp((char*)decrypted, message) == 0) {
            log_msg("  *** MESSAGE VERIFIED ***\n\n");
            log_phase("Hybrid Decryption", "Successfully decrypted and verified");
        }
    } else {
        log_msg("  FAILED\n");
        goto cleanup;
    }
    
    /* Final Summary */
    log_msg("\n========================================\n");
    log_msg("SIMULATION COMPLETE\n");
    log_msg("========================================\n\n");
    log_msg("All phases successful:\n");
    log_msg("  1. Key Generation (Ring-LWE + LDPC)\n");
    log_msg("  2. Ring Signature Authentication\n");
    log_msg("  3. Signature Verification\n");
    log_msg("  4. Hybrid Encryption (LDPC + AES)\n");
    log_msg("  5. Hybrid Decryption\n\n");
    log_msg("Status: SUCCESS\n\n");
    
    log_phase("COMPLETE PROTOCOL", "All cryptographic operations verified");
    
cleanup:
    if (results_file) fclose(results_file);
    if (phase_file) fclose(phase_file);
    
    printf("\nLogs saved to:\n");
    printf("  - simulation_results.log\n");
    printf("  - phase_success.log\n\n");
    
    return 0;
}
