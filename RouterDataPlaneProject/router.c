
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>


#define MAX_ROUTE_ENTRIES 100000
#define ARP_CACHE_SIZE 100

#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806


struct route_table_entry *routing_table = NULL;
int routing_table_size = 0;

struct arp_entry {
    uint32_t ip;
    uint8_t mac[6];
    struct arp_entry *next;
};

struct arp_entry *arp_cache = NULL;

queue pending_packets;

struct pending_packet {
    char buf[MAX_PACKET_LEN];
    size_t len;
    int interface;
    uint32_t next_hop_ip;
};

struct trie_node {
    struct route_table_entry *entry;
    struct trie_node *left;
    struct trie_node *right;
};

// functie care adauga o ruta in trie
void insert_route(struct trie_node **root, struct route_table_entry *entry) {
    // daca radacina nu exista, o alocam
    if (*root == NULL) {
        *root = calloc(1, sizeof(struct trie_node));
    }

    struct trie_node *node = *root;

    uint32_t prefix = ntohl(entry->prefix);
    uint32_t mask = ntohl(entry->mask);
    // extragem nr-ul de biti de 1
    int prefix_len = __builtin_popcount(mask);

    // parcurgem fiecare bit incepand cu cel mai semnificativ
    for (int i = 31; i >= 32 - prefix_len; i--) {
        int bit = (prefix >> i) & 1;

        // mergem la st sau dr in functie de bit
        if (bit == 0) {
            if (!node->left)
                node->left = calloc(1, sizeof(struct trie_node));
            node = node->left;
        } else {
            if (!node->right)
                node->right = calloc(1, sizeof(struct trie_node));
            node = node->right;
        }
    }
    // cand ajungem la finalul prefixului, salvam ruta in nodul respectiv
    node->entry = entry;
}

// functie care cauta cea mai buna ruta
struct route_table_entry *trie_lookup(struct trie_node *root, uint32_t ip) {
    struct route_table_entry *best = NULL;
    struct trie_node *node = root;

    ip = ntohl(ip);

    // iteram de la cel mai semnificativ bit
    for (int i = 31; i >= 0 && node != NULL; i--) {
        // daca gasim o ruta si e mai buna decat ultima gasita, o retinem
        if (node->entry) {
            if (!best || __builtin_popcount(node->entry->mask) > __builtin_popcount(best->mask)) {
                best = node->entry;
            }
        }
        int bit = (ip >> i) & 1;
        node = (bit == 0) ? node->left : node->right;
    }

    return best;
}

// functie pt a cauta o adresa MAC in cache-ul ARP
uint8_t *search_arp_cache(uint32_t ip) {
    struct arp_entry *entry = arp_cache;
    while (entry != NULL) {
        if (entry->ip == ip) {
            return entry->mac;
        }
        entry = entry->next;
    }
    return NULL;
}

// functie pt a adauga o noua intrare in cache-ul ARP
void add_arp_entry(uint32_t ip, uint8_t *mac) {
    struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
    if (new_entry == NULL) {
        perror("Failed to allocate memory for ARP entry");
        return;
    }

    new_entry->ip = ip;
    memcpy(new_entry->mac, mac, 6);
    new_entry->next = arp_cache;
    arp_cache = new_entry;
    
}

// functie pt a trimite un ARP Request
void send_arp_request(uint32_t target_ip, int interface) {
    char buf[MAX_PACKET_LEN];

    // construim header-ele
    struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    // setam destinatia broadcast
    memset(eth_hdr->ethr_dhost, 0xFF, 6);

    get_interface_mac(interface, eth_hdr->ethr_shost);

    eth_hdr->ethr_type = htons(ETH_P_ARP);
    arp_hdr->hw_type = htons(1);
    arp_hdr->proto_type = htons(ETH_P_IP);
    arp_hdr->hw_len = 6;
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(1);

    // completam adresele sursa cu adresele router-ului
    get_interface_mac(interface, arp_hdr->shwa);
    arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));

    memset(arp_hdr->thwa, 0x00, 6);
    arp_hdr->tprotoa = target_ip;

    // trimitem pachetul
    send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
}

// functie pt a trata un ARP Reply
void handle_arp_reply(struct arp_hdr *arp_hdr) {
    // verificam daca IP-ul este deja in cache
    uint8_t *mac = search_arp_cache(arp_hdr->sprotoa);
    if (!mac) {     // daca nu este, il adaugam
        add_arp_entry(arp_hdr->sprotoa, arp_hdr->shwa);
    }

    // cream coada temporara pentru pachetele netrimise
    queue temp_queue = create_queue();

    // laum fiecare pachet netrimis si verificam daca acum avem mac-ul pentru el
    while (!queue_empty(pending_packets)) {
        struct pending_packet *pkt = queue_deq(pending_packets);

        // daca avem mac-ul, trimitem pachetul
        uint8_t *mac = search_arp_cache(pkt->next_hop_ip);
        if (mac) {
            struct ether_hdr *eth_hdr = (struct ether_hdr *)pkt->buf;
            memcpy(eth_hdr->ethr_dhost, mac, 6);
            send_to_link(pkt->len, pkt->buf, pkt->interface);
            free(pkt);
        } else {
            queue_enq(temp_queue, pkt);
        }
    }

    // actualizam lista de pachete netrimise
    pending_packets = temp_queue;
}

// functie care trimite un icmp error
void send_icmp_error(uint8_t type, uint8_t code, char *recv_packet, size_t recv_len, int in_interface) {
    char packet[MAX_PACKET_LEN];

    // extragem header-ele
    struct ether_hdr *recv_eth_hdr = (struct ether_hdr *)recv_packet;
    struct ip_hdr *recv_ip_hdr = (struct ip_hdr *)(recv_packet + sizeof(struct ether_hdr));

    size_t ip_header_len = sizeof(struct ip_hdr);

    // construim header-ele de trimis
    struct ether_hdr *eth_hdr = (struct ether_hdr *)packet;
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    // setam header-ul Ethernet
    get_interface_mac(in_interface, eth_hdr->ethr_shost);
    memcpy(eth_hdr->ethr_dhost, recv_eth_hdr->ethr_shost, 6);
    eth_hdr->ethr_type = htons(ETH_P_IP);

    // setam header-ul ICMP
    icmp_hdr->mtype = type;     // tipul erorii
    icmp_hdr->mcode = code;
    icmp_hdr->check = 0;
    icmp_hdr->un_t.gateway_addr = 0;

    // copiem IP header-ul original si primii 8 bytes din payload
    memcpy(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
           recv_ip_hdr,
           ip_header_len + 8);

    // calculam checksum ICMP
    size_t icmp_total_len = sizeof(struct icmp_hdr) + ip_header_len + 8;
    icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_total_len));

    size_t total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_total_len;
    // trimitem pachetul
    send_to_link(total_len, packet, in_interface);
}

// functie care trimite un icmp reply
void send_icmp_echo_reply(char *recv_packet, size_t recv_len, int in_interface) {
    char packet[MAX_PACKET_LEN];

    // extragem header-ele
    struct ether_hdr *recv_eth_hdr = (struct ether_hdr *)recv_packet;
    struct ip_hdr *recv_ip_hdr = (struct ip_hdr *)(recv_packet + sizeof(struct ether_hdr));
    struct icmp_hdr *recv_icmp_hdr = (struct icmp_hdr *)(recv_packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    // calculam lungimea payload-ului
    size_t icmp_payload_len = recv_len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr);

    //construim header-ele pentru raspuns
    struct ether_hdr *eth_hdr = (struct ether_hdr *)packet;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    // setam header-ul Ethernet
    // destinatarul devine sursa
    memcpy(eth_hdr->ethr_dhost, recv_eth_hdr->ethr_shost, 6);
    get_interface_mac(in_interface, eth_hdr->ethr_shost);
    eth_hdr->ethr_type = htons(ETH_P_IP);

    // setam header-ul IP
    ip_hdr->ver = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + icmp_payload_len);
    ip_hdr->id = htons(0);
    ip_hdr->frag = 0;
    ip_hdr->ttl = 64;
    ip_hdr->proto = IPPROTO_ICMP;
    ip_hdr->checksum = 0;
    ip_hdr->source_addr = inet_addr(get_interface_ip(in_interface));
    ip_hdr->dest_addr = recv_ip_hdr->source_addr;
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

    // setam header-ul ICMP
    memcpy(icmp_hdr, recv_icmp_hdr, icmp_payload_len);
    icmp_hdr->mtype = 0;    // semnalizam ca e reply
    icmp_hdr->check = 0;
    icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_payload_len));

    // trimitem raspunsul
    send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_payload_len, packet, in_interface);
}


int main(int argc, char *argv[])
{
    
    char buf[MAX_PACKET_LEN];
    pending_packets = create_queue();

    // Do not modify this line
    init(argv + 2, argc - 2);

    // alocam spatiu pentru tabela de rutare si o citim
    routing_table = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
    routing_table_size = read_rtable(argv[1], routing_table);

    // inseram fiecare ruta in trie
    struct trie_node *trie_root = NULL;
    for (int i = 0; i < routing_table_size; i++) {
        insert_route(&trie_root, &routing_table[i]);
    }

    while (1) {
        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        if (interface < 0) {
            continue;   
        }

        // parsarea pachetului Ethernet
        struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

        // verific dc pachetul are dim minima pentru un cadru Ethernet
        if (len < sizeof(struct ether_hdr)) {
            printf("Pachet prea scurt, îl arunc\n");
            continue;
        }

        // validarea L2 - verific dc MAC destinatie este pt router sau este broadcast       
        uint8_t mac_router[6];
        get_interface_mac(interface, mac_router);  // obtinem MAC-ul routerului

        // verific dc MAC destination este pt router sau este un pachet de tip broadcast
        if (memcmp(eth_hdr->ethr_dhost, mac_router, 6) != 0 &&
            memcmp(eth_hdr->ethr_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
            continue;
        }

        // aflam tipul de protocol din payload
        uint16_t ether_type = ntohs(eth_hdr->ethr_type);

        if (ether_type == ETH_P_IP) {
            // pachet IPv4 
           
            struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

            // verific dc routerul este destinatia finala
            int is_router_dest = 0;
            for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
                struct in_addr ip_struct;
                ip_struct.s_addr = inet_addr(get_interface_ip(i));
                uint32_t ip_router = ip_struct.s_addr;

                if (ip_hdr->dest_addr == ip_router) {
                    is_router_dest = 1;
                    break;
                }
            }

            // daca pachetul e pentru router si e de tip ICMP
            if (is_router_dest) {
                if (ip_hdr->proto == IPPROTO_ICMP) {
                    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
        
                    // daca e un request, dam un reply
                    if (icmp_hdr->mtype == 8) {
                        send_icmp_echo_reply(buf, len, interface);
                    }
                }
                continue;
            }

            // verific checksum-ul
            uint16_t received_checksum = ntohs(ip_hdr->checksum);
            ip_hdr->checksum = 0;
            uint16_t calculated_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));

            // daca checksum-ul e invalid, arunc pachetul
            if (received_checksum != calculated_checksum) {
                continue;
            }

            // verific TTL, iar daca e expirat, trimitem un ICMP error
            if (ip_hdr->ttl <= 1) {
                send_icmp_error(11, 0, buf, len, interface);
                continue;
            }

            // actualizam TTL si checksum
            ip_hdr->ttl--;
            ip_hdr->checksum = 0;
            ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

            // cautam in tabela de rutare
            struct route_table_entry *best_route = NULL;

            best_route = trie_lookup(trie_root, ip_hdr->dest_addr);

            // daca nu am gasit o ruta, trimitem un ICMP error
            if (!best_route) {
                send_icmp_error(3, 0, buf, len, interface);
                continue;
            }

            // verificam daca se afla in cache
            uint32_t next_hop_ip = best_route->next_hop != 0 ?
                       best_route->next_hop : ip_hdr->dest_addr;

            uint8_t *mac = search_arp_cache(next_hop_ip);

            // daca il gasim, trimitem pachetul
            if (mac) {
                memcpy(eth_hdr->ethr_dhost, mac, 6);
                send_to_link(len, buf, best_route->interface);
            } else {
                // daca nu l-am gasit, il adaugam in lista de asteptare
                struct pending_packet *pkt = malloc(sizeof(struct pending_packet));

                memcpy(pkt->buf, buf, len);
                pkt->len = len;
                pkt->interface = best_route->interface;
                pkt->next_hop_ip = best_route->next_hop;

                queue_enq(pending_packets, pkt);
                // trimitem un ARP request
                send_arp_request(best_route->next_hop, best_route->interface);
            }
        } else if (ether_type == ETH_P_ARP) {
            // selectam header-ul ARP
            struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

            // daca e un ARP reply
            if (ntohs(arp_hdr->opcode) == 2) {
                handle_arp_reply(arp_hdr);
            }
            // daca e un ARP request
            else if (ntohs(arp_hdr->opcode) == 1) {
                // verificam daca este pentru router
                for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
                    struct in_addr ip_struct;
                    ip_struct.s_addr = inet_addr(get_interface_ip(i));
                    uint32_t ip_router = ip_struct.s_addr;

                    // daca e pentru router, pregatim un raspuns
                    if (arp_hdr->tprotoa == ip_router) {
                        char reply_buf[MAX_PACKET_LEN];
                        struct ether_hdr *eth_hdr_reply = (struct ether_hdr *)reply_buf;
                        struct arp_hdr *arp_reply = (struct arp_hdr *)(reply_buf + sizeof(struct ether_hdr));

                        // Ethernet
                        memcpy(eth_hdr_reply->ethr_dhost, arp_hdr->shwa, 6);
                        get_interface_mac(i, eth_hdr_reply->ethr_shost);
                        eth_hdr_reply->ethr_type = htons(ETH_P_ARP);

                        // ARP reply
                        arp_reply->hw_type = htons(1);
                        arp_reply->proto_type = htons(ETH_P_IP);
                        arp_reply->hw_len = 6;
                        arp_reply->proto_len = 4;
                        arp_reply->opcode = htons(2);
                        get_interface_mac(i, arp_reply->shwa);
                        arp_reply->sprotoa = ip_router;
                        memcpy(arp_reply->thwa, arp_hdr->shwa, 6);
                        arp_reply->tprotoa = arp_hdr->sprotoa;

                        send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), reply_buf, i);
                    }
                }
            }
            
        } else {
            // dc este un pachet de alt tip, trecem peste
            fprintf(stderr, "Tip de pachet necunoscut\n");
            continue;
        }
    }

    return 0;
}
