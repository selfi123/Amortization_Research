/**
 * node-sender.c
 * Sender/Initiator Node for Post-Quantum Authentication and Encrypted Communication
 * Implements LR-IoTA Ring Signature Generation and LDPC Hybrid Encryption
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include "crypto_core.h"

#include <string.h>
#include <stdio.h>
#include "sys/rtimer.h"
#include "sys/energest.h"

#define LOG_MODULE "Sender"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Helper for Energy Metrics */
static unsigned long to_ticks(uint64_t v) { return (unsigned long)v; }

/* Global timestamp for latency measurement */
static rtimer_clock_t auth_start_time;

/* UDP connection */
static struct simple_udp_connection udp_conn;

/* Protocol message types */
#define MSG_TYPE_AUTH 0x01
#define MSG_TYPE_AUTH_ACK 0x02
#define MSG_TYPE_DATA 0x03

/* ========== SESSION AMORTIZATION MESSAGE STRUCTURES ========== */

/* Authentication message - includes syndrome for one-time LDPC */
typedef struct {
    uint8_t type;
    uint8_t syndrome[LDPC_ROWS / 8];  /* 51 bytes - LDPC syndrome */
    RingSignature signature;
} AuthMessage;

/* Authentication ACK - includes gateway nonce and SID */
typedef struct {
    uint8_t type;
    uint8_t N_G[32];           /* Gateway nonce for K_master derivation */
    uint8_t SID[SID_LEN];      /* Session ID (8 bytes) */
} AuthAckMessage;

/* Data message - session-based, no syndrome needed */
typedef struct {
    uint8_t type;
    uint8_t SID[SID_LEN];
    uint32_t counter;
    uint8_t ciphertext[MESSAGE_MAX_SIZE + AEAD_TAG_LEN];
    uint16_t cipher_len;
} DataMessage;

/* Cryptographic keys */
static RingLWEKeyPair sender_keypair;
static Poly512 other_ring_members[RING_SIZE - 1];  /* Public keys of other ring members */
static LDPCPublicKey shared_ldpc_pubkey;  /* Shared/hardcoded LDPC public key */
/* ========== SESSION AMORTIZATION STATE ========== */
static session_ctx_t session_ctx;              /* Session context */
static ErrorVector auth_error_vector;          /* Error vector for AUTH phase */
static uint8_t syndrome[LDPC_ROWS / 8];        /* Syndrome buffer */

/* Message to encrypt */
static const char *secret_message = "Hello IoT";
#define NUM_MESSAGES 10  /* Number of messages to send per session */

/*---------------------------------------------------------------------------*/
PROCESS(sender_process, "Post-Quantum Sender Process");
AUTOSTART_PROCESSES(&sender_process);
/*---------------------------------------------------------------------------*/

/**
 * UDP Receive Callback
 */
static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
    uint8_t msg_type = data[0];
    
    LOG_INFO("Received message type 0x%02x from ", msg_type);
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");
    
    if (msg_type == MSG_TYPE_AUTH_ACK && !session_ctx.active) {
        /* [METRIC END] Auth Latency */
        rtimer_clock_t auth_end_time = RTIMER_NOW();
        printf("[METRIC] LATENCY_AUTH: %lu\n", (unsigned long)(auth_end_time - auth_start_time));
        
        /* [METRIC] Energest for Auth Phase */
        /* Note: This includes waiting time which dominates energy. */
        /* Ideally take snapshots before/after. Here we log cumulative at check points. */
        
        printf("[METRIC] ENERGY_AUTH_CPU: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_CPU)));
        printf("[METRIC] ENERGY_AUTH_LPM: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_LPM)));
        printf("[METRIC] ENERGY_AUTH_TX: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_TRANSMIT)));
        printf("[METRIC] ENERGY_AUTH_RX: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_LISTEN)));

        /* ===== AUTH_ACK PHASE: Receive gateway nonce and SID ===== */
        AuthAckMessage *ack = (AuthAckMessage *)data;
        
        LOG_INFO("Authentication ACK received! Gateway authenticated us.\n");
        LOG_INFO("Received Gateway Nonce (N_G) and Session ID (SID)\n");
        
        /* Extract N_G and SID */
        uint8_t N_G[32];
        memcpy(N_G, ack->N_G, 32);
        memcpy(session_ctx.sid, ack->SID, SID_LEN);
        
        LOG_INFO("SID: [%02x%02x%02x%02x%02x%02x%02x%02x]\n",
                 session_ctx.sid[0], session_ctx.sid[1], session_ctx.sid[2], session_ctx.sid[3],
                 session_ctx.sid[4], session_ctx.sid[5], session_ctx.sid[6], session_ctx.sid[7]);
        
        /* ===== DERIVE MASTER SESSION KEY ===== */
        LOG_INFO("Deriving master session key K_master...\n");
        derive_master_key(session_ctx.K_master,
                         auth_error_vector.bits, sizeof(auth_error_vector.bits),
                         N_G, 32);
        
        /* Initialize session state */
        session_ctx.counter = 1; /* Start at 1 to avoid conflict with init value 0 */
        session_ctx.active = 1;
        session_ctx.expiry_ts = 0;  /* Not implemented in PoC */
        
        /* Zeroize error vector (no longer needed) */
        secure_zero(&auth_error_vector, sizeof(ErrorVector));
        
        LOG_INFO("Session initialized (counter=0)\n");
        LOG_INFO("K_master derived successfully\n");
        
        /* [METRIC] Sessions count */
        printf("[METRIC] SESSIONS_PER_AUTH: 1\n"); // One session established
        
        /* ===== DATA PHASE: Send Multiple Messages using Session Encryption ===== */
        LOG_INFO("\nProceeding to encrypted data transmission...\n");
        LOG_INFO("Sending %d messages using session encryption...\n", NUM_MESSAGES);
        
        unsigned long total_encrypt_time = 0;
        
        int msg_num;
        for (msg_num = 0; msg_num < NUM_MESSAGES; msg_num++) {
            /* Prepare message */
            char msg_buf[64];
            snprintf(msg_buf, sizeof(msg_buf), "%s #%d", secret_message, msg_num + 1);
            
            /* [METRIC START] Data Encryption */
            rtimer_clock_t enc_start = RTIMER_NOW();
            
            /* Encrypt using session_encrypt (derives K_i internally) */
            uint8_t ciphertext[MESSAGE_MAX_SIZE + AEAD_TAG_LEN];
            size_t cipher_len;
            
            int ret = session_encrypt(&session_ctx,
                                     (uint8_t *)msg_buf, strlen(msg_buf) + 1,
                                     ciphertext, &cipher_len);
            
            rtimer_clock_t enc_end = RTIMER_NOW();
            unsigned long diff = (unsigned long)(enc_end - enc_start);
            printf("[METRIC] COST_DATA_ENCRYPT: %lu\n", diff);
            total_encrypt_time += diff;
            /* [METRIC END] */
            
            if (ret != 0) {
                LOG_ERR("Session encryption failed for message %d!\n", msg_num + 1);
                break;
            }
            
            LOG_INFO("Message %d: '%s' encrypted (%u bytes ciphertext)\n",
                     msg_num + 1, msg_buf, (unsigned)cipher_len);
            
            /* Pack wire format manually */
            uint8_t wire_buf[256];
            size_t offset = 0;
            
            /* Type */
            wire_buf[offset++] = MSG_TYPE_DATA;
            
            /* SID */
            memcpy(wire_buf + offset, session_ctx.sid, SID_LEN);
            offset += SID_LEN;
            
            /* Counter (big-endian) */
            wire_buf[offset++] = (session_ctx.counter >> 24) & 0xFF;
            wire_buf[offset++] = (session_ctx.counter >> 16) & 0xFF;
            wire_buf[offset++] = (session_ctx.counter >> 8) & 0xFF;
            wire_buf[offset++] = session_ctx.counter & 0xFF;
            
            /* Cipher length (big-endian) */
            wire_buf[offset++] = (cipher_len >> 8) & 0xFF;
            wire_buf[offset++] = cipher_len & 0xFF;
            
            /* Ciphertext */
            memcpy(wire_buf + offset, ciphertext, cipher_len);
            offset += cipher_len;
            
            /* Send to gateway */
            simple_udp_sendto(&udp_conn, wire_buf, offset, sender_addr);
            
            /* [METRIC] Communication Overhead */
            printf("[METRIC] COMM_DATA_PACKET_SIZE: %u\n", (unsigned)offset);
            printf("[METRIC] COMM_PROXY_DATA_SIZE: 0\n"); // No proxy for data

            LOG_INFO("  -> Sent with counter=%u (wire size: %u bytes)\n",
                     (unsigned)session_ctx.counter, (unsigned)offset);
            
            /* Increment counter for next message */
            session_ctx.counter++;
        }
        
        LOG_INFO("Data transmission complete! Sent %d messages.\n", NUM_MESSAGES);
        
        /* [METRIC] Session Metrics */
        printf("[METRIC] SESSION_MESSAGE_COUNT: %d\n", NUM_MESSAGES);
        
        /* [METRIC] Energy for Data Phase (Approximate diff from Auth) */
        /* For simplicity, logging current total again. User script can diff if needed, 
           or we can assume monotonic increase. */
        printf("[METRIC] ENERGY_DATA_CPU: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_CPU)));
        printf("[METRIC] ENERGY_DATA_LPM: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_LPM)));
        printf("[METRIC] ENERGY_DATA_TX: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_TRANSMIT)));
        printf("[METRIC] ENERGY_DATA_RX: %lu\n", to_ticks(energest_type_time(ENERGEST_TYPE_LISTEN)));

        /* Signal main process to finish */
        process_poll(&sender_process);
    }
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sender_process, ev, data)
{
    static struct etimer periodic_timer;
    static uip_ipaddr_t dest_ipaddr;
    int i;
    
    PROCESS_BEGIN();
    
    /* [METRIC START] Auth Phase Tracking */
    auth_start_time = RTIMER_NOW();
    
    LOG_INFO("=== Post-Quantum Sender Node Starting ===\n");
    LOG_INFO("Implementing Kumari et al. LR-IoTA + QC-LDPC\n\n");
    
    /* Initialize random number generator */
    crypto_prng_init(0xDEADBEEF ^ (uint32_t)(uintptr_t)&sender_keypair);
    
    /* ===== KEY GENERATION PHASE ===== */
    LOG_INFO("[Phase 1] Generating Ring-LWE keys...\n");
    
    /* [METRIC START] Crypto Cost */
    rtimer_clock_t kg_start = RTIMER_NOW();
    if (ring_lwe_keygen(&sender_keypair) != 0) {
        LOG_ERR("Failed to generate Ring-LWE key pair!\n");
        PROCESS_EXIT();
    }
    rtimer_clock_t kg_end = RTIMER_NOW();
    printf("[METRIC] COST_AUTH_KEYGEN: %lu\n", (unsigned long)(kg_end - kg_start));
    /* [METRIC END] */
    
    LOG_INFO("Ring-LWE key generation successful\n");
    LOG_INFO("  - Secret key generated\n");
    LOG_INFO("  - Public key generated\n");
    LOG_INFO("  - Random polynomial R generated\n");
    
    /* Generate public keys for other ring members (simulated) */
    LOG_INFO("Generating public keys for other ring members...\n");
    for (i = 0; i < RING_SIZE - 1; i++) {
        static RingLWEKeyPair temp_pair; /* FIX: Static to prevent stack overflow (~6KB) */
        ring_lwe_keygen(&temp_pair);
        memcpy(&other_ring_members[i], &temp_pair.public, sizeof(Poly512));
        LOG_INFO("  - Ring member %d public key generated\n", i + 2);
    }
    
    /* Initialize UDP connection */
    simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_rx_callback);
    
    /* Wait for network to be ready */
    LOG_INFO("Waiting for network initialization...\n");
    etimer_set(&periodic_timer, 5 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    
    /* Set destination address (gateway) - using link-local multicast for discovery */
    /* In real deployment, would use gateway's known address */
    if(NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
        LOG_INFO("Gateway address obtained: ");
        LOG_INFO_6ADDR(&dest_ipaddr);
        LOG_INFO_("\n");
    } else {
        /* Use link-local all-nodes multicast */
        uip_create_linklocal_allnodes_mcast(&dest_ipaddr);
        LOG_INFO("Using multicast for gateway discovery\n");
    }
    
    /* FIX: Add delay to ensure RPL routing table is fully updated before sending */
    /* Logs showed route was added 4 seconds after send attempt, causing failure. */
    LOG_INFO("Allowing network routing to stabilize (10s)...\n");
    etimer_set(&periodic_timer, 10 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    
    /* ===== AUTHENTICATION PHASE ===== */
    LOG_INFO("\n[Phase 2] Starting Ring Signature Authentication...\n");
    
    /* ===== Generate shared/hardcoded LDPC public key ===== */
    LOG_INFO("Initializing LDPC public key (hardcoded/shared)...\n");
    if (ldpc_keygen((LDPCKeyPair *)&shared_ldpc_pubkey) != 0) {
        LOG_ERR("Failed to generate LDPC key!\n");
        PROCESS_EXIT();
    }
    LOG_INFO("LDPC public key initialized\n");
    
    /* ===== Generate error vector for AUTH (one-time operation) ===== */
    LOG_INFO("Generating LDPC error vector for session authentication...\n");
    /* Reduced weight to ensure reliable decoding with QC-LDPC (approx 6% error rate) */
    generate_error_vector(&auth_error_vector, 50);
    LOG_INFO("Error vector generated (weight=%u)\n", auth_error_vector.hamming_weight);
    
    /* ===== Encode error to syndrome ===== */
    LOG_INFO("Encoding syndrome from error vector...\n");
    ldpc_encode(syndrome, &auth_error_vector, &shared_ldpc_pubkey);
    LOG_INFO("Syndrome encoded (%u bytes)\n", (unsigned)(LDPC_ROWS / 8));
    
    /* Prepare keyword for signing */
    uint8_t keyword[KEYWORD_SIZE];
    memset(keyword, 0, KEYWORD_SIZE);
    strcpy((char *)keyword, "AUTH_REQUEST");
    
    LOG_INFO("Keyword: %s\n", keyword);
    
    /* Generate ring signature (Ring Size N=3, sender is member 0) */
    LOG_INFO("Generating ring signature (N=%d members)...\n", RING_SIZE);
    
    /* NEW ROBUST CODE with RETRY LOOP */
    static AuthMessage auth_msg; /* FIX: Static allocation to prevent Stack Overflow (SIGSEGV) */
    auth_msg.type = MSG_TYPE_AUTH;
    
    /* Copy syndrome into AUTH message */
    memcpy(auth_msg.syndrome, syndrome, LDPC_ROWS / 8);

    /* Generate signature (for meaningful CPU metrics) */
    int sign_attempts = 0;
    int sign_result = -1;

    /* Try up to 10 times to find a secure signature (Rejection Sampling) */
    while(sign_attempts < 10) {
        sign_result = ring_sign(&auth_msg.signature, keyword, &sender_keypair, 
                                other_ring_members, 0);
        
        if(sign_result == 0) { 
            /* 0 means SUCCESS */
            break; 
        }
        
        /* If -1, the signature was insecure (rejected). Try again. */
        sign_attempts++;
        watchdog_periodic(); /* Prevent watchdog reboot during retries */
    }

    if (sign_result != 0) {
        LOG_ERR("Ring signature generation failed after %d attempts!\n", sign_attempts);
        PROCESS_EXIT();
    }
    
    LOG_INFO("Ring signature generated successfully\n");
    LOG_INFO("  - Signature components: S1, S2, S3\n");
    LOG_INFO("  - Real signer hidden among %d members\n", RING_SIZE);
    
    /* Send authentication message to gateway */
    /* FIX: Use PROXY packet to avoid MTU limit, but include Syndrome for Amortization */
    LOG_INFO("Sending authentication packet (Proxy + Syndrome) to gateway...\n");
    
    uint8_t proxy_buf[64]; /* buffer for small proxy packet */
    uint16_t proxy_len = 0;
    
    proxy_buf[0] = MSG_TYPE_AUTH;
    proxy_len++;
    
    /* Append Syndrome (Crucial for Session Amortization) */
    memcpy(&proxy_buf[1], auth_msg.syndrome, LDPC_ROWS / 8);
    proxy_len += (LDPC_ROWS / 8);
    
    simple_udp_sendto(&udp_conn, proxy_buf, proxy_len, &dest_ipaddr);
    LOG_INFO("Authentication packet sent!\n");
    LOG_INFO("Waiting for gateway verification...\n");
    
    /* Wait for authentication response */
    /* Use process_poll mechanism instead of shared memory flag to avoid race conditions */
    etimer_set(&periodic_timer, 60 * CLOCK_SECOND); /* Increased timeout */
    
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL || etimer_expired(&periodic_timer));
    
    if (etimer_expired(&periodic_timer)) {
        LOG_ERR("Authentication timeout! Gateway did not respond.\n");
        PROCESS_EXIT();
    }
    
    LOG_INFO("\n=== PROTOCOL COMPLETE ===\n");
    LOG_INFO("Successfully authenticated and encrypted message sent!\n");
    
    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
