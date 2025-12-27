#include <openssl/evp.h>    // Biblioteca para funções de alto nível (EVP)
#include <openssl/ec.h>     // Definições específicas para Curvas Elípticas
#include <stdio.h>          // Entrada e saída padrão
#include <string.h>         // Manipulação de strings e memória

/**
 * Função Auxiliar: print_hex
 * Objetivo: Transformar dados binários (bytes) em texto hexadecimal para podermos ver no terminal.
 */
void print_hex(const char *label, unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]); // Imprime cada byte em formato de 2 caracteres hexadecimais
    }
    printf("\n");
}

int main() {
    printf("--- SIMULAÇÃO DE TÚNEL TLS 1.3 (PASSO A PASSO) ---\n\n");

    /* -------------------------------------------------------------------------
     * PASSO 0: O ACORDO PÚBLICO (A COR AMARELA)
     * Antes de começar, os dois precisam concordar em qual "campo" vão jogar.
     * ------------------------------------------------------------------------- */
    
    // EVP_PKEY_CTX: É o "Contexto". Imagine como uma prancheta onde o computador anota 
    // as configurações da operação que vai realizar.
    EVP_PKEY_CTX *ctx_config = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); 
    
    // Inicializa a prancheta para "Geração de Parâmetros"
    EVP_PKEY_keygen_init(ctx_config); 
    
    // NID_X9_62_prime256v1: Este é o nome técnico da "COR AMARELA". 
    // É a curva NIST P-256, usada por quase todos os sites HTTPS no mundo.
    // Essa curva é a base matemática para todo o processo de troca de chaves. É a nossa "cor base amarela" da analogia.
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_config, NID_X9_62_prime256v1);

    // Entao podemos chamar esse "set" de cor base como "configuração de curva elíptica".

    /* -------------------------------------------------------------------------
     * PASSO 1: O CLIENTE (MAQUININHA) GERA SEU SEGREDO
     * Representa o Círculo 1 da nossa imagem (Hello, Key Share).
     * ------------------------------------------------------------------------- */
    
    // EVP_PKEY: É a estrutura que guarda a Chave. Ela contém a parte privada e a pública.
    EVP_PKEY *client_key = NULL; 
    
    // EVP_PKEY_keygen: Gera o par de chaves do cliente.
    // MATEMÁTICA: O cliente cria o VERMELHO (Privado) e o mistura com o AMARELO 
    // para gerar o LARANJA (Público).
    EVP_PKEY_keygen(ctx_config, &client_key); 
    printf("[CLIENTE] Gerou seu segredo interno (VERMELHO) e seu mix público (LARANJA).\n");

    // Em que momento eu digo que é o vermelho?
    // você não diz; o computador inventa um. O que importa é que ele guarda isso na estrutura EVP_PKEY.

    /* -------------------------------------------------------------------------
     * PASSO 2: O SERVIDOR (BANCO) GERA SEU SEGREDO
     * Representa o Círculo 2 da sua imagem (Key Share, Verify).
     * ------------------------------------------------------------------------- */
    
    EVP_PKEY *server_key = NULL;
    
    // O servidor cria seu próprio contexto (sua própria prancheta)
    EVP_PKEY_CTX *ctx_server_gen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx_server_gen);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_server_gen, NID_X9_62_prime256v1);
    
    // MATEMÁTICA: O servidor cria o AZUL (Privado) e o mistura com o AMARELO 
    // para gerar o VERDE (Público).
    EVP_PKEY_keygen(ctx_server_gen, &server_key);
    printf("[SERVIDOR] Gerou seu segredo interno (AZUL) e seu mix público (VERDE).\n\n");

    /* -------------------------------------------------------------------------
     * PASSO 3: A MISTURA FINAL (CALCULANDO O SHARED SECRET)
     * O momento em que o "Marrom" é criado em cada lado separadamente.
     * ------------------------------------------------------------------------- */

    // --- LADO DO CLIENTE ---
    // O Cliente pega o mix VERDE que veio do servidor (Seta 2 da imagem)
    EVP_PKEY_CTX *ctx_derive_client = EVP_PKEY_CTX_new(client_key, NULL);
    // ctx_derive_client é o espaço físico na memória onde a mistura das cores acontece
    // Ao ser criado com o comando EVP_PKEY_CTX_new(client_key, NULL), ele "puxa" o segredo interno do cliente.

    EVP_PKEY_derive_init(ctx_derive_client);
    EVP_PKEY_derive_set_peer(ctx_derive_client, server_key); // Peer = O outro lado (Banco)
    // Em uma conexão entre sua maquininha e o banco, a maquininha vê o banco como o seu peer.
    // Ela vincula a chave pública recebida do "outro lado" (Banco) ao contexto de cálculo do cliente.
    // Agora o ctx_derive_client tem o vermelho (privado do cliente) e o verde (público do servidor).
    
    size_t client_secret_len;
    // Primeiro chamamos para saber o tamanho do segredo que será gerado
    EVP_PKEY_derive(ctx_derive_client, NULL, &client_secret_len);
    unsigned char *client_shared_secret = malloc(client_secret_len);
    
    // MATEMÁTICA: VERMELHO (privado dele) + VERDE (recebido) = MARROM
    EVP_PKEY_derive(ctx_derive_client, client_shared_secret, &client_secret_len);

    // --- LADO DO SERVIDOR ---
    // O Servidor pega o mix LARANJA que veio da maquininha (Seta 1 da imagem)
    EVP_PKEY_CTX *ctx_derive_server = EVP_PKEY_CTX_new(server_key, NULL);
    EVP_PKEY_derive_init(ctx_derive_server);
    EVP_PKEY_derive_set_peer(ctx_derive_server, client_key); // Peer = O outro lado (Cliente)

    size_t server_secret_len;
    EVP_PKEY_derive(ctx_derive_server, NULL, &server_secret_len);
    unsigned char *server_shared_secret = malloc(server_secret_len);
    
    // MATEMÁTICA: AZUL (privado dele) + LARANJA (recebido) = MARROM
    EVP_PKEY_derive(ctx_derive_server, server_shared_secret, &server_secret_len);

    /* -------------------------------------------------------------------------
     * PASSO 4: VERIFICAÇÃO (O TÚNEL ESTÁ PRONTO)
     * ------------------------------------------------------------------------- */
    
    print_hex("[CLIENTE] Chave final (MARROM)", client_shared_secret, client_secret_len);
    print_hex("[SERVIDOR] Chave final (MARROM)", server_shared_secret, server_secret_len);

    if (memcmp(client_shared_secret, server_shared_secret, client_secret_len) == 0) {
        printf("\nRESULTADO: O segredo coincide! A partir de agora, o túnel usa AES com essa chave.\n");
    }

    // Limpeza de memória (Importante em C)
    free(client_shared_secret); free(server_shared_secret);
    EVP_PKEY_free(client_key); EVP_PKEY_free(server_key);
    EVP_PKEY_CTX_free(ctx_config); EVP_PKEY_CTX_free(ctx_derive_client);
    EVP_PKEY_CTX_free(ctx_derive_server); EVP_PKEY_CTX_free(ctx_server_gen);

    return 0;
}