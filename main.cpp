#include "funciones.h" 

int main(int argc, char **argv)
{   
    pcap_if_t *devs = nullptr; //dispositivos que pueden capturar datos 
    char errbuf[PCAP_ERRBUF_SIZE] = {}; //para mensaje de error
    bpf_u_int32 address_net ; //direccion de red en modo raw 
    bpf_u_int32 mask_net    ; //mascara de red en modo raw 
    char *direccion_red = nullptr; 
    char *mascara_red   = nullptr;   
    char ip[15] = {}; 
    pcap_t *descriptor = nullptr; // descriptor para captura 

    /* se hara solo para eth0 */
    /* cada vez que falla una función debe limpiarse las variable */ 

    // todos las interfaces que pueden capturar datos
    if (pcap_findalldevs(&devs, errbuf) != 0) 
    {
        printf("Error obteniedo interfaces: %s\n", errbuf);  
        return 1; 
    }
    
    // direccion ipV4 de eth0
    if (obtener_direcion_ip(devs, ip) == nullptr)
    {
        printf("Error no se pudo obtener la dirección ip\n");
        return 1; 
    }
    printf("Ip: %s\n", ip); 
    
    // la direccion y mascara de red de la interface eth0  
    if(obtener_direccion_red_mascara(&address_net, &mask_net, errbuf) == 1)
    {
        printf("Error obteniedo direccion de red y mascara: %s\n", errbuf);
        return 1;
    }
    
    // direccion de red
    if(mostrar_direccion_red(address_net, mask_net, direccion_red, errbuf) != 0)
    {
        printf("Error obteniendo direccion de red: %s\n", errbuf);
        return 1; 
    } 
    
    // mascara de red
    if(mostrar_mascara_red(address_net, mask_net, mascara_red, errbuf) != 0)
    {
        printf("Error obteniendo direccion de red: %s\n", errbuf); 
        return 1;
    }

    // descriptor
    if((descriptor = obtenemos_descriptor(errbuf)) == nullptr) 
    {
        printf("Error obteniendo descriptor: %s\n", errbuf); 
        return 1; 
    } 

    // procesar paquetes 
    pcap_loop(descriptor, 0, proceso_paquete_callback, nullptr); 

    //
    limpiar_variables(devs, direccion_red, mascara_red, descriptor); 

    //
    return 0;
}
