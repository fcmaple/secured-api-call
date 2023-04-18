#include "liba.h"
int (*libc_open)(const char *, int,  mode_t);
size_t (*libc_read)(int,  void *, size_t);
ssize_t (*libc_write)(int,  const void *, size_t);
ssize_t (*libc_connect)(int , const struct sockaddr *, socklen_t );
int (*libc_getaddrinfo)(const char *,const char *,const struct addrinfo *,struct addrinfo **);
int (*libc_system)(const char*);
char* operation[]={"open","read","write","system","connect","getaddrinfo"};
unsigned long operationGOT[10];
char blacklist[10][100][1000]; 
char* black_read;
int open_len,read_len,write_len,system_len,connect_len,getaddrinfo_len,max_len;
char connectip[MAX_IP_LENGTH];
char exeName[50]={0};

enum operation{
    OPEN,
    READ,
    WRITE,
    SYSTEM,
    CONNECT,
    GETADDRINFO,
    PORT
};
int getlogfd() {
    char *fd_str = getenv("LOGGER_FD");
    int fd_int = 0;
    if(fd_str == NULL) return STDERR_FILENO;
    while(*fd_str){
        fd_int=((*fd_str)-'0') + fd_int*10;
        fd_str++;
    }
    return fd_int;
}
size_t read_test(int fd, void *buf, size_t count){
    //get pid fd read.log
    pid_t pid = getpid();
    char filename[20];
    sprintf(filename,"{%d}-{%d}-read.log",pid,fd);
    size_t len = 0;
    size_t r = 0;
    char write_buffer[100000];
    char read_buffer[100000];
    r = (*libc_read)(fd,write_buffer,count); // write_buffer to read  the content
    if(!r){
        dprintf(getlogfd(),"[logger] read(%d,%p,%lu)=%lu\n",fd,buf,count,r);
        return r;
    }
    FILE* read_fp = fopen(filename,"r"); //read;
    int cnt=0;
    if(read_fp){
        //load file
        fseek(read_fp,(-1)*max_len,SEEK_END);
        cnt = fread(read_buffer,sizeof(char),max_len,read_fp);
        fclose(read_fp);
    }
    int r_len = strlen(read_buffer);
    int w_len = strlen(write_buffer);
    strcat(read_buffer,write_buffer);
    for(int i=0;i<(r_len+w_len);i++){
        for(int j=0;j<read_len;j++){
            if(!strncmp(read_buffer+i,blacklist[READ][j],strlen(blacklist[READ][j]))){
                close(fd);
                dprintf(getlogfd(),"[logger] read(%d,%p,%lu)=%d\n",fd,buf,count,-1);
                errno = EIO;
                return -1;
            }
        }
    }

    FILE* write_fp = fopen(filename,"a");
    fwrite(write_buffer,sizeof(char),r,write_fp);//write to file from buffer
    fclose(write_fp);

    memcpy(buf,write_buffer,r);
    
    dprintf(getlogfd(),"[logger] read(%d,%p,%lu)=%lu\n",fd,buf,count,r);
    return r;
}
int open_test(const char *pathname, int flags , ...){//check symbolic link
    // int (*addr)(const char*,int,mode_t) = original[0]; //real open
    va_list ap;
    va_start(ap,flags);
    mode_t mode = va_arg(ap,mode_t);
    struct stat filestat;
    char linkname[1024]={0};
    int fd=0;
    if(lstat(pathname,&filestat)==-1){
        fd = -1;
    }
    if(S_ISLNK(filestat.st_mode)){
        if(realpath(pathname,linkname)==NULL){
            fd =  -1;
        }
    }else{
        strcpy(linkname,pathname);
    }
    for(int i=0;i<open_len;i++){
        if(!strcmp(blacklist[OPEN][i],linkname)){
            errno = EACCES;
            fd = -1;
        }
    }
    if(!fd) fd =(*libc_open)(linkname,flags,mode);
    
    dprintf(getlogfd(),"[logger] open(\"%s\",%d,%o)=%d\n",pathname,flags,mode&0777,fd);
    return fd;
}
ssize_t write_test(int fd, const void *buf, size_t count){
    ssize_t r;
    pid_t pid = getpid();
    char filename[20];
    
    sprintf(filename,"{%d}-{%d}-write.log",pid,fd);
    FILE* write_fp = fopen(filename,"a");
    fwrite(buf,sizeof(char),count,write_fp);//change??
    r = (*libc_write)(fd,buf,count);
    fclose(write_fp);
    
    dprintf(getlogfd(),"[logger] write(%d,%p,%lu)=%lu\n",fd,buf,count,r);
    return r;
}
int connect_test(int sockfd, const struct sockaddr *addr,socklen_t addrlen)
{
    const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
    const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;

    char ip_str[20];
    uint16_t port=0;
    if (addr->sa_family == AF_INET) {
        // IPv4
        inet_ntop(AF_INET, &addr4->sin_addr, ip_str, sizeof(ip_str));
        port = ntohs(addr4->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        // IPv6
        inet_ntop(AF_INET6, &addr6->sin6_addr, ip_str, sizeof(ip_str));
        port = ntohs(addr6->sin6_port);
    } 
    int flag=0;
    char pport[20];
    sprintf(pport,"%u",port);
    for(int i=0;i<connect_len;i++){
        if(!strcmp(connectip,blacklist[CONNECT][i]) && !strcmp(pport,blacklist[PORT][i])){
            flag=1;
            break;
        }
    }
    if(flag){
        errno = ECONNREFUSED;
        dprintf(getlogfd(),"[logger] connect(%d,\"%s\",%u)=%d\n",sockfd,ip_str,addrlen,-1);
        return -1;
    }
    int res = (*libc_connect)(sockfd,addr,addrlen);
    dprintf(getlogfd(),"[logger] connect(%d,\"%s\",%u)=%d\n",sockfd,ip_str,addrlen,res);
    return res;
}
int getaddrinfo_test(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    int flag=0;
    for(int i=0;i<getaddrinfo_len;i++){
        if(!strcmp(node,blacklist[GETADDRINFO][i])){
            flag=1;
            errno=EAI_NONAME;
        }
    }
    if(flag){
        dprintf(getlogfd(),"[logger] getaddrinfo(\"%s\",\"%s\",%p,%p)=%d\n",node,service,hints,res,EAI_NONAME);
        return EAI_NONAME;
    }
    int ret = (*libc_getaddrinfo)(node,service,hints,res);

    strcpy(connectip,node);
    dprintf(getlogfd(),"[logger] getaddrinfo(\"%s\",\"%s\",%p,%p)=%d\n",node,service,hints,res,ret);
    return ret;
}
int system_test(const char* command){
    dprintf(getlogfd(),"[logger] system(%s)\n",command);
    int res = (*libc_system)(command);
    return res;
}

void get_segement(){
    long segment[5];
    FILE *fp;
    char* line=NULL;
    size_t len = 0;
    int count = 0;    
    fp = fopen("/proc/self/maps","r");
    while(getline(&line, &len, fp)>0){
        // printf("%s\n",line);
        char* base_addr = strtok(line,"-");
        long number =strtol(base_addr, NULL, 16);
        segment[count++] = number;
        if(count==5) break;
    }
    if(mprotect((void*)segment[3],segment[4]-segment[3],PROT_READ|PROT_WRITE)==-1){
        fprintf(stderr,"mprotect %d!\n",errno);
    }
    int operation_len = sizeof(operationGOT)/sizeof(unsigned long);
    for(int i=0;i<6;i++){
        if(operationGOT[i]!=0){
            operationGOT[i] = operationGOT[i]+segment[0]; // 1310 GOT entry-> need to overwrite the code_0 function
            void (*addr)();
            switch(i){
                case OPEN:
                    libc_open = &open;
                    addr = &open_test;
                    break;
                case READ:
                    libc_read = &read;
                    addr = &read_test;
                    break;
                case WRITE:
                    libc_write = &write;
                    addr = &write_test;
                    break;
                case CONNECT:
                    libc_connect = &connect;
                    addr = &connect_test;
                    break;
                case GETADDRINFO:
                    libc_getaddrinfo = &getaddrinfo;
                    addr = &getaddrinfo_test;
                    break;
                case SYSTEM:
                    libc_system = &system;
                    addr = &system_test;
                    break;
                default:
                    break;
            }
            long *a = operationGOT[i];
            *a = addr; //GOT table
        }
    }
    return;
}

int load_blacklist(const char* blackname,enum operation op){
    char start_buf[20];
    char end_buf[20],end_buf1[20];
    FILE *fp;
    char line[1024];
    size_t len = 0;
    int flag=0,count=0;
    char* configName = getenv("SANDBOX_CONFIG");
    fp = fopen(configName,"r");
    sprintf(start_buf,"BEGIN %s-blacklist\n",blackname);
    sprintf(end_buf,"END %s-blacklist\n",blackname);
    sprintf(end_buf1,"END %s-blacklist",blackname);

    while(fgets(line, sizeof(line), fp)){
        int status=0,count_ip=0;
        if(!strcmp(end_buf,line) || !strcmp(end_buf1,line)) break;
        if(flag) {
            if(op==CONNECT){
                char* host = strtok(line,":");
                char* port = strtok(NULL,":");
                strncpy(blacklist[op][count],line,strlen(line));
                strncpy(blacklist[PORT][count],port,strlen(port)-1);
            }else if(op==OPEN){
                struct stat filestat;
                char linkname[1024]={0};
                char pathname[1024]={0};
                strncpy(pathname,line,strlen(line)-1);
            
                if(realpath(pathname,linkname)==NULL){
                    errno = EACCES;
                }

                strncpy(blacklist[op][count],linkname,strlen(linkname));
                count++;

            }else if(op==READ){
                
                if((strlen(line)-1)>max_len) {
                    max_len = strlen(line)-1;
                }
                strncpy(blacklist[op][count],line,strlen(line)-1);
            }else{
                strncpy(blacklist[op][count],line,strlen(line)-1);
            }
            
            count++;
        }
        if(!strcmp(start_buf,line)) flag=1;
        
    }

    fclose(fp);
    return count;
}
void load_all_black_list(){
    open_len = load_blacklist("open",OPEN);
    read_len = load_blacklist("read",READ);
    write_len = load_blacklist("write",WRITE);
    connect_len = load_blacklist("connect",CONNECT);
    getaddrinfo_len = load_blacklist("getaddrinfo",GETADDRINFO);
}

void getOpGot(char **argv){

    if (realpath("/proc/self/exe", exeName) == NULL) {
        perror("realpath");
        exit(EXIT_FAILURE);
    }

    FILE *fp = fopen(exeName, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s\n", exeName);
        exit(EXIT_FAILURE);
    }

    Elf64_Ehdr elf_header; //header
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp) != 1) {
        fprintf(stderr, "Failed to read ELF header from file %s\n", exeName);
        _exit(EXIT_FAILURE);
    }


    Elf64_Shdr *shdr_table = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
    if (!shdr_table) {
        fprintf(stderr, "Failed to allocate memory for section header table\n");
        _exit(EXIT_FAILURE);
    }
    fseek(fp, elf_header.e_shoff, SEEK_SET);// section header start 
    if (fread(shdr_table, sizeof(Elf64_Shdr), elf_header.e_shnum, fp) != elf_header.e_shnum) {
        fprintf(stderr, "Failed to read section header table from file %s\n", exeName);
        exit(EXIT_FAILURE);
    }
    Elf64_Shdr *rela_plt_hdr = NULL;
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    int str_count=0;
    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (shdr_table[i].sh_type == SHT_RELA ) {
            rela_plt_hdr = &shdr_table[i];
        }
        else if (shdr_table[i].sh_type == SHT_DYNSYM) {
            symtab_hdr = &shdr_table[i];
        }
        else if (shdr_table[i].sh_type == SHT_STRTAB && str_count==0) {
            strtab_hdr = &shdr_table[i];
            str_count=1;
        }
    }
    if (!rela_plt_hdr) {
        fprintf(stderr, "Failed to find .rela.plt section in file %s\n", exeName);
        _exit(EXIT_FAILURE);
    }

    if (!symtab_hdr) {
        fprintf(stderr, "Failed to find symbol table section in file %s\n", exeName);
        _exit(EXIT_FAILURE);
    }

    if (!strtab_hdr) {
        fprintf(stderr, "Failed to find string table section in file %s\n", exeName);
        _exit(EXIT_FAILURE);
    }
    fseek(fp, rela_plt_hdr->sh_offset, SEEK_SET);
    size_t num_relocations = rela_plt_hdr->sh_size / rela_plt_hdr->sh_entsize;
    Elf64_Rela *relocations = (Elf64_Rela *)malloc(sizeof(Elf64_Rela) * (num_relocations));
    if (!relocations) {
        fprintf(stderr, "Failed to allocate memory for relocations\n");
        _exit(EXIT_FAILURE);
    }

    if (fread(relocations, rela_plt_hdr->sh_entsize, num_relocations, fp) != num_relocations) {
        fprintf(stderr, "Failed to read relocations from file %s\n", exeName);
        _exit(EXIT_FAILURE);
    }
    fseek(fp, symtab_hdr->sh_offset, SEEK_SET);
    size_t num_symbols = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
    Elf64_Sym *symbols = (Elf64_Sym *)malloc(sizeof(Elf64_Sym) * num_symbols);
    if (!symbols) {
        fprintf(stderr, "Failed to allocate memory for symbols\n");
        exit(EXIT_FAILURE);
    }

    if (fread(symbols, symtab_hdr->sh_entsize, num_symbols, fp) != num_symbols) {
        fprintf(stderr, "Failed to read symbols from file %s\n", exeName);
        _exit(EXIT_FAILURE);
    }

    fseek(fp, strtab_hdr->sh_offset, SEEK_SET);
    char *strtab = (char *)malloc(strtab_hdr->sh_size);
    if (!strtab) {
        fprintf(stderr, "Failed to allocate memory for string table\n");
        _exit(EXIT_FAILURE);
    }

    if (fread(strtab, 1, strtab_hdr->sh_size, fp) != strtab_hdr->sh_size) {
        fprintf(stderr, "Failed to read string table from file %s\n", exeName);
        _exit(EXIT_FAILURE);
    }
    for (int i = 0; i < num_relocations; i++) {
        Elf64_Rela *rela = &relocations[i];
        // printf("%d,%ld,%ld\n",i,ELF64_R_TYPE(rela->r_info),R_X86_64_JUMP_SLOT);
        if (ELF64_R_TYPE(rela->r_info) == R_X86_64_JUMP_SLOT) {
            Elf64_Sym *sym = &symbols[ELF64_R_SYM(rela->r_info)];
            char *symname = &strtab[sym->st_name];
            for(int j=0;j<6;j++){
                if(strlen(symname)==strlen(operation[j])&&strncmp(symname,operation[j],strlen(operation[j]))==0){
                    operationGOT[j] = rela->r_offset;
                }
            }
        }
    }
    fclose(fp);
    free(relocations);
    free(symbols);
    free(strtab);
}

int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    void (*init)(void),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end
){
    load_all_black_list();
    getOpGot(argv);
    get_segement();
    

    void* handle = dlopen("libc.so.6",RTLD_LAZY);
    if(!handle){
        perror("handle");
        _exit(0);
    }

    int (*libc_start)(int (*)(int, char **, char **),int,char **,\
    void (*)(void),void (*)(void),void (*)(void),void *);

    libc_start = dlsym(handle,"__libc_start_main");
    return (*libc_start)(main,argc,argv,init,fini,rtld_fini,stack_end);
}
