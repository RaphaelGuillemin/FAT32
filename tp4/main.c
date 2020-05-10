/**
 * Laura Bégin 20093040
 * Raphael Guillemin 20129638
 */

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
#pragma ide diagnostic ignored "hicpp-signed-bitwise"
#pragma ide diagnostic ignored "readability-non-const-parameter"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define FAT_NAME_LENGTH 11 //longueur d'un nom de fichier en fat 11 caractères
#define FAT_EOC_TAG 0x0FFFFFF8 //end of chain tag
#define FAT_DIR_ENTRY_SIZE 32 //size of d'une entrée en bits
#define HAS_NO_ERROR(err) ((err) >= 0)
#define NO_ERR 0
#define GENERAL_ERR -1
#define OUT_OF_MEM -3
#define RES_NOT_FOUND -4
#define CAST(t, e) ((t) (e)) //caster
#define as_uint16(x) \
((CAST(uint16,(x)[1])<<8U)+(x)[0])
#define as_uint32(x) \
((((((CAST(uint32,(x)[3])<<8U)+(x)[2])<<8U)+(x)[1])<<8U)+(x)[0])

typedef unsigned char uint8;
typedef uint8 bool;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef int error_code;

/**
 * Pourquoi est-ce que les champs sont construit de cette façon et non pas directement avec les bons types?
 * C'est une question de portabilité. FAT32 sauvegarde les données en BigEndian, mais votre système de ne l'est
 * peut-être pas. Afin d'éviter ces problèmes, on lit les champs avec des macros qui convertissent la valeur.
 * Par exemple, si vous voulez lire le paramètre BPB_HiddSec et obtenir une valeur en entier 32 bits, vous faites:
 *
 * BPB* bpb;
 * uint32 hidden_sectors = as_uint32(BPB->BPP_HiddSec);
 *
 */
typedef struct BIOS_Parameter_Block_struct {
    uint8 BS_jmpBoot[3];
    uint8 BS_OEMName[8];
    uint8 BPB_BytsPerSec[2];  // 512
    uint8 BPB_SecPerClus;     // 1
    uint8 BPB_RsvdSecCnt[2];  // 1 for FAT12 and FAT16, typically 32 for FAT32
    uint8 BPB_NumFATs;        // should be 2
    uint8 BPB_RootEntCnt[2];
    uint8 BPB_TotSec16[2];
    uint8 BPB_Media;
    uint8 BPB_FATSz16[2];
    uint8 BPB_SecPerTrk[2];
    uint8 BPB_NumHeads[2];
    uint8 BPB_HiddSec[4];
    uint8 BPB_TotSec32[4];
    uint8 BPB_FATSz32[4]; //504
    uint8 BPB_ExtFlags[2];
    uint8 BPB_FSVer[2];
    uint8 BPB_RootClus[4];
    uint8 BPB_FSInfo[2];
    uint8 BPB_BkBootSec[2];
    uint8 BPB_Reserved[12];
    uint8 BS_DrvNum;
    uint8 BS_Reserved1;
    uint8 BS_BootSig;
    uint8 BS_VolID[4];
    uint8 BS_VolLab[11];
    uint8 BS_FilSysType[8];
} BPB;

typedef struct FAT_directory_entry_struct {
    uint8 DIR_Name[FAT_NAME_LENGTH];
    uint8 DIR_Attr;
    uint8 DIR_NTRes;
    uint8 DIR_CrtTimeTenth;
    uint8 DIR_CrtTime[2];
    uint8 DIR_CrtDate[2];
    uint8 DIR_LstAccDate[2];
    uint8 DIR_FstClusHI[2];
    uint8 DIR_WrtTime[2];
    uint8 DIR_WrtDate[2];
    uint8 DIR_FstClusLO[2];
    uint8 DIR_FileSize[4];
} FAT_entry;

uint8 ilog2(uint32 n) {
    uint8 i = 0;
    while ((n >>= 1U) != 0)
        i++;
    return i;
}

//--------------------------------------------------------------------------------------------------------
//                                           DEBUT DU CODE
//--------------------------------------------------------------------------------------------------------
//uint32 begin = as_uint16(block->BPB_RsvdSecCnt) * as_uint16(block->BPB_BytsPerSec) + as_uint32(block->BPB_HiddSec) * as_uint16(block->BPB_BytsPerSec) + block->BPB_NumFATs * as_uint32(block->BPB_FATSz32) * as_uint16(block->BPB_BytsPerSec);

/**
 * Exercice 1
 *
 * Prend cluster et retourne son addresse en secteur dans l'archive
 * @param block le block de paramètre du BIOS
 * @param cluster le cluster à convertir en LBA
 * @param first_data_sector le premier secteur de données, donnée par la formule dans le document
 * @return le LBA
 */
uint32 cluster_to_lba(BPB *block, uint32 cluster, uint32 first_data_sector) {
    if(block == NULL){
        return GENERAL_ERR;
    }
    //First data sector est le begin (information sortie du discord)
    return first_data_sector + (cluster - as_uint32(block->BPB_RootClus)) * block->BPB_SecPerClus * as_uint16(block->BPB_BytsPerSec);
}

/**
 * Exercice 2
 *
 * Va chercher une valeur dans la cluster chain
 * @param block le block de paramètre du système de fichier
 * @param cluster le cluster qu'on veut aller lire
 * @param value un pointeur ou on retourne la valeur
 * @param archive le fichier de l'archive
 * @return un code d'erreur
 */
error_code get_cluster_chain_value(BPB *block,
                                   uint32 cluster,
                                   uint32 *value,
                                   FILE *archive) {
    if(block == NULL || value == NULL){
        return GENERAL_ERR;
    }
    //avancer tete de lecture jusque la table fat
    fseek(archive,as_uint16(block->BPB_BytsPerSec) * (as_uint16(block->BPB_RsvdSecCnt) + as_uint32(block->BPB_HiddSec)) + cluster * FAT_DIR_ENTRY_SIZE/8,SEEK_SET);
    uint8 *chain_value = malloc(FAT_DIR_ENTRY_SIZE/8);
    if(chain_value == NULL){
        return GENERAL_ERR;
    }
    //Lire 4 bytes (taille d'une entrée de la table fat)
    for(int i = 0 ; i < 4 ; i++) {
        if(i != 3) {
            chain_value[i] = fgetc(archive);
            // remplacer 4 bits significatifs par des 0
        } else {
            chain_value[i] = fgetc(archive) % 0x10;
        }
    }
    memcpy(value,chain_value,FAT_DIR_ENTRY_SIZE/8);
    free(chain_value);
    return 0;
}

bool emptyString(FAT_entry* entry, int j) {
    for (int i = j; i < FAT_NAME_LENGTH; i++) {
        if (entry->DIR_Name[i] != ' ') {
            return 0;
        }
    }
}

/**
 * Exercice 3
 *
 * Vérifie si un descripteur de fichier FAT identifie bien fichier avec le nom name
 * @param entry le descripteur de fichier
 * @param name le nom de fichier
 * @return 0 ou 1 (faux ou vrai)
 */
bool file_has_name(FAT_entry *entry, char *name) {
    if(entry == NULL || name == NULL){
        return GENERAL_ERR;
    }
    //si entrée vide
    if(entry->DIR_Name[0] == 0x00 && strlen(name) == 0){
        return 1;
    } else if (entry->DIR_Name[0] == 0x00 && strlen(name) != 0){
        return 0;
    }
    // si . ou ..
    if(entry->DIR_Name[0] == '.' && name[0] == '.') {
        if (entry->DIR_Name[1] == '.' && name[1] == '.' && strlen(name) == 2) {
            if (emptyString(entry, 2)) {
                return 1;
            } else {
                return 0;
            }
        } else if (strlen(name) == 1) {
            if (emptyString(entry, 1)) {
                return 1;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }
    //j = index du string de entry name
    int j = 0;
    for(int i=0;i < strlen(name);i++){
        if(name[i] != '.') {
            char charUpper = (char) toupper(name[i]);
            if (charUpper == entry->DIR_Name[j]) {
                j++;
                continue;
            } else {
                return 0;
            }
        } else {
            //verifier espaces jusqu'a l'extension du fichier
            for(j = i; j < FAT_NAME_LENGTH - 3; j++){
                if(entry->DIR_Name[j] != ' '){
                    return 0;
                }
            }

        }
    }
    return 1;
}

//mettre \0 a chaque position d'un string
void cleanString(char* string, int length){
    for (int i = 0 ; i < length; i++){
        string[i] = '\0';
    }
}

/**
 * Exercice 4
 *
 * Prend un path de la forme "/dossier/dossier2/fichier.ext et retourne la partie
 * correspondante à l'index passé. Le premier '/' est facultatif.
 * @param path l'index passé
 * @param level la partie à retourner (ici, 0 retournerait dossier)
 * @param output la sortie (la string)
 * @return -1 si les arguments sont incorrects, -2 si le path ne contient pas autant de niveaux
 * -3 si out of memory
 */
error_code break_up_path(char *path, uint8 level, char **output) {
    if(path == NULL || output == NULL){
        return GENERAL_ERR;
    }
    //ignorer le / de debut de chaine si présent
    if(path[0] == '/'){
        path++;
    }

    int niveau = level;
    int length = 0;
    char *outputString = malloc(sizeof(char) * FAT_NAME_LENGTH+1);
    cleanString(outputString, FAT_NAME_LENGTH + 1);
    //garder premier pointeur du string en memoire
    char *firstChar = outputString;
    for(int i = 0; path[i] != '\0' && niveau >= 0; i++){
        //attendre d'etre au bon niveau pour lire le nom du dossier ou du fichier souhaite
        if(path[i] == '/'){
            niveau--;
            continue;
        }
        //lire le nom du fichier au bon endroit
        if(niveau == 0){
            if(length > FAT_NAME_LENGTH){
                return OUT_OF_MEM;
            }
            *outputString = path[i];
            outputString++;
            length++;
        }

    }
    *outputString = '\0';

    if(niveau>0){
        free(outputString);
        return -2;
    }
    *output = malloc(sizeof(char) * length+1);
    cleanString(*output,length);
    memcpy(*output,firstChar,sizeof(char) * length+1);
    outputString = firstChar;
    free(outputString);
    return length;
}


/**
 * Exercice 5
 *
 * Lit le BIOS parameter block
 * @param archive fichier qui correspond à l'archive
 * @param block le block alloué
 * @return un code d'erreur
 */
error_code read_boot_block(FILE *archive, BPB **block) {
    if(archive == NULL || block == NULL){
        return GENERAL_ERR;
    }
    uint8* boot_block = malloc(sizeof(BPB));
    if(boot_block == NULL){
        return GENERAL_ERR;
    }
    //lire bloc important des 512 premiers bytes
    fgets(boot_block, sizeof(BPB),archive);
    memcpy(*block,boot_block, sizeof(BPB));
    free(boot_block);
    return 0;
}

/**
 * Exercice 6
 *
 * Trouve un descripteur de fichier dans l'archive
 * @param archive le descripteur de fichier qui correspond à l'archive
 * @param path le chemin du fichier
 * @param entry l'entrée trouvée
 * @return un code d'erreur
 */
error_code find_file_descriptor(FILE *archive, BPB *block, char *path, FAT_entry **entry) {
    if(block == NULL || archive == NULL || path == NULL || entry == NULL){
        return GENERAL_ERR;
    }
    bool found = 0;
    //placer la tete de lecture au bon endroit
    uint32 begin = as_uint16(block->BPB_RsvdSecCnt) * as_uint16(block->BPB_BytsPerSec) + as_uint32(block->BPB_HiddSec) * as_uint16(block->BPB_BytsPerSec) + block->BPB_NumFATs * as_uint32(block->BPB_FATSz32) * as_uint16(block->BPB_BytsPerSec);
    uint32 lba = cluster_to_lba(block,as_uint32(block->BPB_RootClus),begin);
    FAT_entry* fatEntry = malloc(sizeof(FAT_entry));
    if(fatEntry == NULL){
        return GENERAL_ERR;
    }
    char **output = malloc(sizeof(char *) * FAT_NAME_LENGTH);
    if(output == NULL){
        free(fatEntry);
        return GENERAL_ERR;
    }

    uint32 clusterFirstFile = as_uint32(block->BPB_RootClus);

    int i = 0;
    int profondeur = 0;
    int j = 0;

    //trouver profondeur du path
    while(break_up_path(path,profondeur,output) != -2){
        profondeur++;
        free(*output);
        *output = NULL;
    }

    while(!found){
        //trouve prochain cluster si on a lu 512 bytes
        if(i >= as_uint16(block->BPB_BytsPerSec) / FAT_DIR_ENTRY_SIZE){
            uint32 *newCluster = malloc(sizeof(uint32)+1);
            get_cluster_chain_value(block,clusterFirstFile,newCluster,archive);
            if(*newCluster >= FAT_EOC_TAG || newCluster == NULL){
                free(fatEntry);
                free(newCluster);
                return GENERAL_ERR;
            }
            clusterFirstFile = *newCluster;
            free(newCluster);
            lba = cluster_to_lba(block,clusterFirstFile,begin);
            i = 0;
        }
        //aller au byte du dossier ou du fichier dans la fat table
        fseek(archive,lba + FAT_DIR_ENTRY_SIZE*i,SEEK_SET);
        fgets(fatEntry, sizeof(FAT_entry),archive);
        //error in path
        if(*output == NULL && break_up_path(path,j,output) == -2){
            free(fatEntry);
            free(*output);
            free(output);
            return GENERAL_ERR;
        }
        if(file_has_name(fatEntry,*output)){
            free(*output);
            *output = NULL;
            //si fichier ou dossier cherché, finir
            if(profondeur-1 == j) {
                found = 1;
            //si dossier faisant parti du path, continuer
            } else {
                //si fichier utilisé comme dossier dans un path
                if(fatEntry->DIR_Attr == ' '){
                    //changer attribut pour que read file n'essaye pas le lire le fichier
                    fatEntry->DIR_Attr = 'a';
                    free(fatEntry);
                    free(output);
                    return GENERAL_ERR;
                }
                //trouver cluster prochain dossier
                clusterFirstFile = (as_uint16(fatEntry->DIR_FstClusHI) << 16) + as_uint16(fatEntry->DIR_FstClusLO);;
                if(clusterFirstFile == 0){
                    clusterFirstFile = as_uint32(block->BPB_RootClus);
                }
                lba = cluster_to_lba(block,clusterFirstFile,begin);
                j++;
                i = 0;
                continue;
            }
        }
        i++;
    }
    *entry = malloc(sizeof(FAT_entry));
    memcpy(*entry,fatEntry, sizeof(FAT_entry));

    free(fatEntry);
    free(output);
    return 0;
}

/**
 * Exercice 7
 *
 * Lit un fichier dans une archive FAT
 * @param entry l'entrée du fichier
 * @param buff le buffer ou écrire les données
 * @param max_len la longueur du buffer
 * @return un code d'erreur qui va contenir la longueur des donnés lues
 */
error_code read_file(FILE *archive, BPB *block, FAT_entry *entry, void *buff, size_t max_len) {
    if(archive == NULL || block == NULL || entry == NULL || buff == NULL || entry->DIR_Attr != ' '){
       return GENERAL_ERR;
    }
    //trouver le cluster de data
    uint32 clusterFirstFile =(as_uint16(entry->DIR_FstClusHI) << 16) + as_uint16(entry->DIR_FstClusLO);
    uint32 *nextCluster = malloc(sizeof(uint32));
    if(nextCluster == NULL) {
        return GENERAL_ERR;
    }

    int cluster = 1;
    uint32 begin = as_uint16(block->BPB_RsvdSecCnt) * as_uint16(block->BPB_BytsPerSec) + as_uint32(block->BPB_HiddSec) * as_uint16(block->BPB_BytsPerSec) + block->BPB_NumFATs * as_uint32(block->BPB_FATSz32) * as_uint16(block->BPB_BytsPerSec);
    uint32 lba = cluster_to_lba(block,clusterFirstFile,begin);
    char *buffer = (char *) buff;
    fseek(archive,lba,SEEK_SET);
    int i = 0;
    for(; i <= as_uint32(entry->DIR_FileSize) && i <= max_len ; i++){
        //si le nombre de bytes lu est plus grand que le nombre de bytes d'un cluster, trouver le prochain cluster
        if(i >= as_uint16(block->BPB_BytsPerSec) * cluster){
            get_cluster_chain_value(block,clusterFirstFile,nextCluster,archive);
            if(*nextCluster >= FAT_EOC_TAG){
                free(nextCluster);
                return i-1;
            }
            clusterFirstFile = *nextCluster;
            lba = cluster_to_lba(block,*nextCluster,begin);
            fseek(archive,lba,SEEK_SET);
            cluster++;
        }
        buffer[i] = (char)fgetc(archive);
        if(i+1 < max_len) {
            buffer[i + 1] = '\0';
        }
    }
    free(nextCluster);
    return i-1;
}

void runTests(FILE * fp, BPB * bpb){
    //EX1
    uint32 begin = as_uint16(bpb->BPB_RsvdSecCnt) * as_uint16(bpb->BPB_BytsPerSec) + as_uint32(bpb->BPB_HiddSec) * as_uint16(bpb->BPB_BytsPerSec) + bpb->BPB_NumFATs * as_uint32(bpb->BPB_FATSz32) * as_uint16(bpb->BPB_BytsPerSec);
    uint32 resultLba = cluster_to_lba(bpb,2,begin);
    assert(resultLba == 532480);
    resultLba = cluster_to_lba(bpb,3,begin);
    assert(resultLba == 532992);
    resultLba = cluster_to_lba(bpb,105,begin);
    assert(resultLba == 585216);

    //EX2
    uint32 *value = malloc(sizeof(uint32)+1);
    get_cluster_chain_value(bpb,4,value,fp);
    assert(*value == 0x5);
    get_cluster_chain_value(bpb,as_uint32(bpb->BPB_RootClus),value,fp);
    assert(*value == FAT_EOC_TAG);
    free(value);

    //EX3
    FAT_entry* fatEntry = malloc(sizeof(FAT_entry));
    uint8* name = (uint8*)"TEST    TXT";
    memcpy(fatEntry->DIR_Name,name,sizeof(fatEntry->DIR_Name));
    assert(file_has_name(fatEntry,"test.txt")==1);
    name = (uint8*)"UNFICHIETXT";
    memcpy(fatEntry->DIR_Name,name,sizeof(fatEntry->DIR_Name));
    assert(file_has_name(fatEntry,"unfichie.txt")==1);
    name = (uint8*)"PETIT   ";
    memcpy(fatEntry->DIR_Name,name,sizeof(fatEntry->DIR_Name));
    assert(file_has_name(fatEntry,"petit.txt")==0);
    name = (uint8*)"DOSSIER    ";
    memcpy(fatEntry->DIR_Name,name,sizeof(fatEntry->DIR_Name));
    assert(file_has_name(fatEntry,"dossier")==1);
    free(fatEntry);

    //EX4
    char **output = malloc(sizeof(char*)*FAT_NAME_LENGTH);
    int size = break_up_path("/dossier/dossier2/fichier.ext",1,output);
    assert(strcmp(*output,"dossier2") == 0);
    assert(size == 8);
    free(*output);
    free(output);

    //EX6 et 7
    FAT_entry **fatEntry1 = malloc(sizeof(FAT_entry *));
    find_file_descriptor(fp,bpb,"/afolder/./another/../another/candide.txt",fatEntry1);
    FAT_entry *fatEntry2 = *fatEntry1;
    assert(as_uint32(fatEntry1[0]->DIR_FileSize) == 225009);
    void *buffer = malloc(sizeof(uint8) * as_uint32(fatEntry2->DIR_FileSize)+1);
    size = read_file(fp,bpb,*fatEntry1,buffer,as_uint32(fatEntry2->DIR_FileSize));
    //printf("contenu : %s\nsize : %i\n",buffer, size);
    free(buffer);
    free(*fatEntry1);

    find_file_descriptor(fp,bpb,"/hello.txt",fatEntry1);
    fatEntry2 = *fatEntry1;
    assert(as_uint32(fatEntry2->DIR_FileSize) == 26);
    buffer = malloc(sizeof(uint8) * as_uint32(fatEntry2->DIR_FileSize)+1);
    size = read_file(fp,bpb,*fatEntry1,buffer,as_uint32(fatEntry2->DIR_FileSize));
    printf("contenu : %s\n size : %i\n",buffer, size);
    free(buffer);
    free(*fatEntry1);

    find_file_descriptor(fp,bpb,"/spanish/los.txt",fatEntry1);
    fatEntry2 = *fatEntry1;
    buffer = malloc(sizeof(uint8) * as_uint32(fatEntry2->DIR_FileSize)+1);
    size = read_file(fp,bpb,*fatEntry1,buffer,as_uint32(fatEntry2->DIR_FileSize));
    //printf("contenu : %s\n size : %i\n",buffer, size);
    free(buffer);
    free(*fatEntry1);

    find_file_descriptor(fp,bpb,"/spanish/titan.txt",fatEntry1);
    fatEntry2 = *fatEntry1;
    buffer = malloc(sizeof(uint8) * as_uint32(fatEntry2->DIR_FileSize)+1);
    size = read_file(fp,bpb,*fatEntry1,buffer,as_uint32(fatEntry2->DIR_FileSize));
    //printf("contenu : %s\nsize : %i\n",buffer, size);
    free(buffer);
    free(*fatEntry1);

    find_file_descriptor(fp,bpb,"/spanish/titan.txt/./",fatEntry1);
    fatEntry2 = *fatEntry1;
    buffer = malloc(sizeof(uint8) * as_uint32(fatEntry2->DIR_FileSize)+1);
    size = read_file(fp,bpb,*fatEntry1,buffer,as_uint32(fatEntry2->DIR_FileSize));
    //printf("contenu : %s\nsize : %i\n",buffer, size);
    free(buffer);
    free(*fatEntry1);

    find_file_descriptor(fp,bpb,"/zola.txt",fatEntry1);
    buffer = malloc(sizeof(uint8) * as_uint32(fatEntry1[0]->DIR_FileSize)+1);
    size = read_file(fp,bpb,*fatEntry1,buffer,as_uint32(fatEntry1[0]->DIR_FileSize));
    //printf("contenu : %s\nsize : %i\n",buffer, size);
    free(buffer);
    free(*fatEntry1);

    free(fatEntry1);
}


int main(int argc, char *argv[]) {
    /*
     * Vous êtes libre de faire ce que vous voulez ici.
     */
    BPB* bpb = malloc(sizeof(BPB));
    FILE *fp = fopen("floppy.img","rb");
    if (fp == NULL){
        printf("error : %d\n",errno);
        return GENERAL_ERR;
    }
    //EX5
    read_boot_block(fp,&bpb);

    //TESTS
    runTests(fp,bpb);

    //FREE
    free(bpb);
    fclose(fp);
    return 0;
}

