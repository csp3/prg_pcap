#include "funciones.h" 

using namespace std; 

// direccion ipV4 de eth0 
char* obtener_direcion_ip(pcap_if_t *devs, char ip[])
{
    char *aux_ip  = nullptr;
    pcap_if_t *it = devs; 
    while (it != nullptr)
    {
        if (string(it->name) == "eth0")
        {
            for (pcap_addr_t *a = it->addresses; a != NULL; a = a->next)
            {
                // mostrar ipV4
                if(a->addr->sa_family == AF_INET)
                {
                    aux_ip = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
                    // pasando a la variable ip 
                    snprintf(ip, strlen(aux_ip) + 1, "%s", aux_ip); 
                } 
            }
            break;
        }
        it = it->next; 
    }
    //
    return aux_ip;
}

// la direccion y mascara de red de la interface eth0 
bpf_u_int32 obtener_direccion_red_mascara(bpf_u_int32 *address_net, bpf_u_int32 *mask_net, char errbuf[])
{
    if (pcap_lookupnet("eth0", address_net, mask_net, errbuf) == -1) 
    { 
        return 1;
    }
    return *address_net;
}

// direccion de red 
int mostrar_direccion_red(bpf_u_int32 address_net, bpf_u_int32 mask_net, char *direccion_red, char errbuf[]) 
{
    struct in_addr addr;
    addr.s_addr = address_net;  
    if ((direccion_red = inet_ntoa(addr)) == NULL)   
    {
        return 1; 
    }
    printf("Direccion de red: %s\n", direccion_red); 
    return 0;
} 

// mascara de red 
int mostrar_mascara_red(bpf_u_int32 address_net, bpf_u_int32 mask_net, char *mascara_red, char errbuf[])
{
    struct in_addr addr;
    addr.s_addr = mask_net;
    if ((mascara_red = inet_ntoa(addr)) == nullptr) 
    {
        return 1; 
    }
    printf("Mascara de red: %s\n", mascara_red); 
    return 0; 
} 

// obtener descriptor para captura 
pcap_t* obtenemos_descriptor(char errbuf[]) 
{
    return pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); 
} 

// obtener descriptor para captura 
void proceso_paquete_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
    static int n=0;      
    printf("%d\n", n++); 
}

// limpiar variables 
void limpiar_variables(pcap_if_t *devs, char *direccion_red, char *mascara_red, pcap_t *descriptor)
{
    direccion_red = nullptr;
    mascara_red   = nullptr;
    free(direccion_red);
    free(mascara_red);
    pcap_close(descriptor);  
    pcap_freealldevs(devs);
}
