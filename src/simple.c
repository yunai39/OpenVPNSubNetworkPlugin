/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * This file implements a OpenVPN module to be able to 
 * give client different Realm for user based on the certificat name pattern
 */

#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "openvpn-plugin.h"

#define INDEX_NETWORK 0
#define INDEX_REGEX 1
#define INDEX_NETMASK 2
// TODO : It should be 3 but I have a bug that I need to correct
#define NUM_PARAM_CONF 4

/*
 * Each subnet_ip correspond to an ip address
 */
typedef struct subnet_ip{
    char *address;
    int used;
    char *common_name;
}subnet_ip;
 

/*
 * Client context information
 */
typedef struct plugin_per_client_context {
  subnet_ip *ip;
  char* generated_conf_file;
}plugin_per_client_context;

/*
 * Each subnet config
 */
typedef struct realm_conf{
    const char *network;
    const char *netmask;
    const char *regex;
    int start[4];
    int end[4];
    subnet_ip **subnet;
 }realm_conf;
 
 /*
  * The full plugin context, with the different configuration
  */
 typedef struct plugin_context{
  char *conf_dir;
  char *plugin_conf;
  int numRealm;
  realm_conf **configs;
}plugin_context;

//Todo: move it in a header
static int get_nb_line(char *file_name);
static int get_config(struct plugin_context *context, const char *argv[], const char *envp[]);
static int generate_subnet(struct plugin_context *context, const char *argv[], const char *envp[]);




/*
 * Free Context: This function will free the context for the plugin 
 */
static int free_plugin_context(plugin_context * context){
    int i;
    for(i = 0; context->configs[i] ; i++){
        for(i = 0; context->configs[i]->subnet[i] ; i++){
            free(context->configs[i]->subnet[i]);
        }
        free(context->configs[i]->subnet);
        free(context->configs[i]);
    }
    free(context->configs);
    return 0;
}

/*
 *  Given an environmental variable name, search
 *  the envp array for its value, returning it
 *  if found or NULL otherwise.
 */
static const char *
get_env (const char *name, const char *envp[])
{
  if (envp)
    {
      int i;
      const int namelen = strlen (name);
      for (i = 0; envp[i]; ++i)
        {
          if (!strncmp (envp[i], name, namelen))
            {
              const char *cp = envp[i] + namelen;
              if (*cp == '=')
                return cp + 1;
            }
        }
    }
  return NULL;
}


/*
 * Found an ip address available in the array of teh subnet
 */
struct subnet_ip *
found_ip_realm(const char *name, struct realm_conf *conf){
    int i=0;
    printf("PLUGIN_REALM: found_ip_realm %s netmask\n", conf->network);
    for (i =0 ; conf->subnet[i] ;i++){
        if(conf->subnet[i]->used == 0){
            conf->subnet[i]->used = 1;
            conf->subnet[i]->common_name = strdup(name);
            return conf->subnet[i];
        }
    }
    return NULL;
}



/* 
 * matchhere: search for regexp at beginning of text 
 */
int matchhere(char *regexp, char *text)
{
	if (regexp[0] == '\0')
		return 1;
	if (regexp[1] == '*')
		return matchstar(regexp[0], regexp+2, text);
	if (regexp[0] == '$' && regexp[1] == '\0')
		return *text == '\0';
	if (*text!='\0' && (regexp[0]=='.' || regexp[0]==*text))
		return matchhere(regexp+1, text+1);
	return 0;
}

/*
 * match: search for regexp anywhere in text 
 */
int match(char *regexp, char *text)
{
	if (regexp[0] == '^')
		return matchhere(regexp+1, text);
	do {	/* must look even if string is empty */
		if (matchhere(regexp, text))
			return 1;
	} while (*text++ != '\0');
	return 0;
}

/*
 * matchstar: search for c*regexp at beginning of text 
 */
int matchstar(int c, char *regexp, char *text)
{
	do {	/* a * matches zero or more instances */
		if (matchhere(regexp, text))
			return 1;
	} while (*text != '\0' && (*text++ == c || c == '.'));
	return 0;
}
/*
 * Need to lookup for the IP, then create the file
 */
static int
client_connect (struct plugin_context *context, const char *argv[], const char *envp[], struct plugin_per_client_context *client_ip){
    int i;
    const char *common_name = NULL;
    common_name = strdup(get_env("common_name",envp));
    printf("PLUGIN_REALM: common_name %s\n",common_name);
    // For each subnet
    for(i = 0; i< context->numRealm;i++){
        char *regex = NULL;
        regex = strdup(context->configs[i]->regex);
        printf("PLUGIN_REALM: commonname - %s\n",common_name);
        printf("PLUGIN_REALM: regex - %s\n",regex);
        printf("PLUGIN_REALM: network - %s\n",context->configs[i]->network);
        printf("PLUGIN_REALM: netmask - %s\n",context->configs[i]->netmask);
            // Look if the common_name of the certificate correspond to the regex
        if(match(regex, common_name )){
            printf("PLUGIN_REALM: Match founded for %s in Realm Number %d with regex %s\n",common_name,i, regex);
            char conf[256];
            char filename[256];
            FILE * file = NULL;
            subnet_ip *ip = NULL;
            ip = found_ip_realm(common_name,context->configs[i] );
            // If we found an ip address
            if(ip != NULL){
                // filename
                sprintf(filename,"%s%s",context->conf_dir,common_name);
                // Configuration
                sprintf(conf,"ifconfig-push %s %s",ip->address,context->configs[i]->netmask);
                // Open the file
                file = fopen(filename, "w+");
                printf("PLUGIN_REALM: Configuration file generated for %s with ip %s\n",common_name,ip->address);
                // Write the output file
                fprintf(file, "ifconfig-push %s %s",ip->address,context->configs[i]->netmask);
                fclose(file);
                
                // Edit the client context
                client_ip->ip = ip;
                client_ip->generated_conf_file = strdup(filename);
                return OPENVPN_PLUGIN_FUNC_SUCCESS;
            }else{
                sprintf(filename,"%s%s",context->conf_dir,common_name);
                unlink(filename);
                return OPENVPN_PLUGIN_FUNC_ERROR;
            }
        }else{
            printf("PLUGIN_REALM: No match founded for %s in Realm %d with regex %s",common_name, i,regex);
        }
    }
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

/*
 * On client disconnection we need to clean the file
 */
static int
client_disconnect (struct plugin_context *context, const char *argv[], const char *envp[], struct plugin_per_client_context *client_conf){
      char filename[256];
      if(client_conf->ip != NULL){
          printf("PLUGIN_REALM_DISCONNECT: ip address %s", client_conf->ip->address);  
          // Delete the file concerning the configuration
          sprintf(filename,"%s%s",context->conf_dir,client_conf->ip->common_name);
          unlink(filename);
          // relase the ip in the global conf

          client_conf->ip->common_name = NULL;
          client_conf->ip->used = 0;
      }
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/*
 * Number of line in a file (used to know how many configuration) 
 */
static int
get_nb_line(char *file_name){
    FILE *fh = fopen(file_name, "r");
    int lines = 0;
    char line[1024];
    lines = 0;
    while( fgets(line,sizeof(line),fh) != NULL)
       lines++;
    fclose(fh);
    return lines;
}

/*
 * Generate the subnet in the memory, this way when we need to look up for an ip, we just have to look inside an array
 */
static int 
generate_subnet(struct plugin_context *context, const char *argv[], const char *envp[])
{
    int count,compter,i,j,k;
    char buf[256];

    // For each subnet
    for(i = 0; i < context->numRealm;i++){
        count = (context->configs[i]->end[2] - context->configs[i]->start[2] + 1) * (context->configs[i]->end[3] - context->configs[i]->start[3] + 1);
        printf("PLUGIN_REALM: NUM SUBNET %d\n\n",count);
        context->configs[i]->subnet = malloc(count * sizeof(subnet_ip *));
        compter = 0;
        
        for(j = context->configs[i]->start[2]; j <= context->configs[i]->end[2] ; j++){
            for(k = context->configs[i]->start[3]; k <= context->configs[i]->end[3] ; k++){
                // Do not give the subnet address
                if(j == context->configs[i]->start[2] && k == context->configs[i]->start[3]){
                    printf("PLUGIN_REALM: Address Ip network: %d.%d.%d.%d\n",context->configs[i]->start[0],context->configs[i]->start[1],j,k);
                }
                // Do not give the first address
                else if(j == context->configs[i]->start[2] && k == context->configs[i]->start[3] + 1){
                     printf("PLUGIN_REALM: Address Ip Gateway network: %d.%d.%d.%d\n",context->configs[i]->start[0],context->configs[i]->start[1],j,k);
                }
                // Do not give the netmask address
                else if(j == context->configs[i]->end[2] && k == context->configs[i]->end[3]){
                     printf("PLUGIN_REALM: Address Brodcast network: %d.%d.%d.%d\n",context->configs[i]->start[0],context->configs[i]->start[1],j,k);
                }
                else if(j == context->configs[i]->end[2] && k == context->configs[i]->end[3]-1){
                     printf("PLUGIN_REALM: Address DHCP network: %d.%d.%d.%d\n",context->configs[i]->start[0],context->configs[i]->start[1],j,k);
                }
                else{
                    context->configs[i]->subnet[compter] = malloc(sizeof(subnet_ip));
                    context->configs[i]->subnet[compter]->used = 0;
                    sprintf(buf,"%d.%d.%d.%d",context->configs[i]->start[0],context->configs[i]->start[1],j,k);
                    context->configs[i]->subnet[compter]->address = strdup(buf);
                    compter++;
                }
            }
        }
    }
    return 0;
}

/*
 * Generate the configuration
 */
static int
get_config(struct plugin_context *context, const char *argv[], const char *envp[])
{
    FILE *fh = fopen(context->plugin_conf, "r");
    char * line = NULL;
    char * buf = NULL;
    int i,j;
    size_t len = 0;
    ssize_t read;
    context->configs = malloc(context->numRealm * sizeof(realm_conf **) );
    i=0;
    // read for the realm_conf
    while ((read = getline(&line, &len, fh)) != -1) {
        buf = strtok(line, "#");
        context->configs[i] = malloc(sizeof(realm_conf *) );
        for(j = 0 ; j < NUM_PARAM_CONF; j++){
            switch (j)
                {
                case INDEX_REGEX:
                  context->configs[i]->regex = strdup(buf);
                  break;
                case INDEX_NETWORK:
                  context->configs[i]->network = strdup(buf);
                  break;
                case INDEX_NETMASK:
                  context->configs[i]->netmask = strdup(buf);
                  break;
            }
            buf = strtok(NULL, "#");
        }
        i++;
    }
    fclose(fh);
    printf("====================== REALM CONF ======================\n");
    for(i= 0; i< context->numRealm; i++){
        // make start
        char *netmaskTMP = strdup(context->configs[i]->netmask);
        char *addressTMP = strdup(context->configs[i]->network);
        char *regexTMP = strdup(context->configs[i]->regex);
        printf("Realm number %d\n",i+1);
        printf("Regex  %s\n",regexTMP);
        printf("network  %s\n",addressTMP);
        printf("netmask  %s\n",netmaskTMP);
        
        buf = strtok(addressTMP, ".");
        for(j = 0;j < 4; j++){
            context->configs[i]->start[j] = atoi(buf);
            buf = strtok(NULL, ".");
        }
        // make end
        buf = strtok(netmaskTMP, ".");
        for(j = 0;j < 4; j++){
            context->configs[i]->end[j] = context->configs[i]->start[j] + 255 - atoi(buf);
            buf = strtok(NULL, ".");
        }
    }
    
    
    return 0;
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
    struct plugin_context *context;
    int i;
    /*
     *    Allocate our context
     */
    context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context))    ;
    printf("PLUGIN_REALM: PLUGIN_CONFIGURATION\n");
    context->plugin_conf = strdup(argv[1]);
    printf("PLUGIN_REALM: PLUGIN_CONFIGURATION_FILE: %s\n",strdup(argv[1] ));
    context->conf_dir = strdup(argv[2]);
    printf("PLUGIN_REALM: PLUGIN_CONFIGURATION_DIR: %s\n",strdup(argv[2]) );

    context->numRealm = get_nb_line(context->plugin_conf);
    // Fetch the configuration
    i = get_config (context, argv, envp);
    // Generate the subnet
    i = generate_subnet(context, argv, envp);
    /*
     *  We are only interested in intercepting the
     *  --auth-user-pass-verify callback.
     */
    *type_mask =
    
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_IPCHANGE) |
    OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_DISCONNECT);

    return (openvpn_plugin_handle_t) context;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v2 (openvpn_plugin_handle_t handle,
			const int type,
			const char *argv[],
			const char *envp[],
			void *per_client_context,
			struct openvpn_plugin_string_list **return_list)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    struct plugin_per_client_context *client_conf = (struct plugin_per_client_context *) per_client_context;
    switch (type)
        { 
        case OPENVPN_PLUGIN_IPCHANGE:
            printf ("PLUGIN_REALM: OPENVPN_PLUGIN_IPCHANGE\n");
            return  client_connect (context, argv, envp, client_conf);
        case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
            printf ("PLUGIN_REALM: OPENVPN_PLUGIN_CLIENT_DISCONNECT\n");
            return  client_disconnect (context, argv, envp, client_conf);
        default:
            printf ("PLUGIN_REALM: OPENVPN_PLUGIN_?\n");
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1 (openvpn_plugin_handle_t handle)
{
  printf ("PLUGIN_REALM: openvpn_plugin_client_constructor_v1\n");
  return calloc (1, sizeof (struct plugin_per_client_context));
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1 (openvpn_plugin_handle_t handle, void *per_client_context)
{
    printf ("PLUGIN_REALM: openvpn_plugin_client_destructor_v1\n");
    if(per_client_context != NULL){
        free (per_client_context);
    }
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  struct plugin_context *context = (struct plugin_context *) handle;
  free_plugin_context(context);
}
