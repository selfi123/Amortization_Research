/**
 * project-conf.h
 * Contiki-NG Configuration for Post-Quantum Cryptography Implementation
 * Based on Kumari et al. "A post-quantum lattice based lightweight authentication
 * and code-based hybrid encryption scheme for IoT devices"
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Network Configuration */
#define UDP_PORT 5678
#define NETSTACK_CONF_WITH_IPV6 1

/* Buffer and Stack Size Configuration */
/* Large stack needed for 512-degree polynomial operations */
#ifndef PROCESS_CONF_STACKSIZE
#define PROCESS_CONF_STACKSIZE 4096
#endif
#define UIP_CONF_BUFFER_SIZE 1280

/* Enable printf support for debugging */
#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_MAIN LOG_LEVEL_DBG

/* Memory optimization */
#define NBR_TABLE_CONF_MAX_NEIGHBORS 4
#define UIP_CONF_MAX_ROUTES 4

/* Crypto work buffer size - for polynomial operations */
#define CRYPTO_WORK_BUFFER_SIZE 2048

/* Enable UDP support */
#define UIP_CONF_UDP 1

/* Disable RPL DAG MC (Metric Container) to save memory */
#define RPL_CONF_WITH_MC 0

#endif /* PROJECT_CONF_H_ */
