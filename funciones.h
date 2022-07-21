#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string>
#include <cstring> // strlen y no coliciones con strlen de string.h
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

// direccion ipV4 de eth0
char* obtener_direcion_ip(pcap_if_t *devs, char ip[]); 

// la direccion y mascara de red de la interface eth0
bpf_u_int32 obtener_direccion_red_mascara(bpf_u_int32 *address_net, bpf_u_int32 *mask_net, char errbuf[]); 

// direccion de red 
int mostrar_direccion_red(bpf_u_int32 address_net, bpf_u_int32 mask_net, char *direccion_red, char errbuf[]); 

// mascara de red 
int mostrar_mascara_red(bpf_u_int32 address_net, bpf_u_int32 mask_net, char *mascara_red, char errbuf[]); 

// obtener descriptor para captura 
pcap_t* obtenemos_descriptor(char errbuf[]); 

// procesar paquete
void proceso_paquete_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// limpiar variables
void limpiar_variables(pcap_if_t *devs, char *direccion_red, char *mascara_red, pcap_t *descriptor); 
