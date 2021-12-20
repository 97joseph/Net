#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
  

#define BUFFER_LENGTH 256

char * create_line(void){

     int fd = open("/dev/fw_log", O_RDONLY);
    if(fd == -1)
    { perror("open failed"); return 0; }

    FILE* fout = fopen("log.txt", "a");
    if(fout == NULL)
    { close(fd); perror("fopen failed, log.txt is busy!"); return 0; }

    while (1) 
    {
        char buffer[BUFFER_LENGTH];
        int ret = read(fd, buffer, sizeof(buffer));
        if (ret == 0)
            break;
        if (ret == -1) 
        {
            perror("Failed to read the message from the device.");
            return errno;
        }
        fwrite(buffer, 1, ret, fout);
        //fprintf(fout, "%s", buffer);
    }

    fclose(fout);
    close(fd);
    return 0;
}
    

    






int get_number_of_lines(FILE *fp);

long int lines =0;

int get_number_of_lines(FILE *fp){
if ( fp == NULL ) {
    return -1;
  }

  while (EOF != (fscanf(fp, "%*[^\n]"), fscanf(fp,"%*c")))
        ++lines;


  printf("Lines : %li\n", lines);

return lines;
}

char * concatenate_strings(const char** strings)
{
    int i = 0;              /* Loop index               */
    int count = 0;          /* Count of input strings   */
    char * result = NULL;   /* Result string            */
    int totalLength = 0;    /* Length of result string  */


    /* Check special case of NULL input pointer. */
    if (strings == NULL)
    {
        return NULL;
    }

    /* 
     * Iterate through the input string array,
     * calculating total required length for destination string.
     * Get the total string count, too.
     */
    while (strings[i] != NULL)
    {
        totalLength += strlen(strings[i]);
        i++;
    }
    count = i;
    totalLength++;  /* Consider NUL terminator. */

    /*
     * Allocate memory for the destination string.
     */
    result = malloc(sizeof(char) * totalLength);
    if (result == NULL) 
    {
        /* Memory allocation failed. */
        return NULL;
    }

    /*
     * Concatenate the input strings.
     */
    for (i = 0; i < count; i++) 
    {
        strcat(result, strings[i]);
    }

    return result;
}



int load_rules(char * filepath) {

  FILE *fp;
  fp=fopen(filepath, "r");
  long int lines =get_number_of_lines(fp);
  char * line = NULL;
  
    size_t len = 0;
    int i=0;
    int max=0;
    int bytesWritten=0;
    ssize_t read;
    

  

if(lines==-1){
return -1;
}

char *all_lines [lines+1];
fp=fopen(filepath, "r");


  if (fp == NULL)
        exit(1);

    while ((read = getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %zu:\n", read);
        //max size of line

        if(read>max){
         max=read;
        }

        strcat(line,"\n");
        all_lines[i] = (char*)malloc(sizeof(char)*strlen(line));
        sprintf(all_lines[i],"%s",line);
        printf("%s", all_lines[i]);
        i++;
    }


all_lines[i] =NULL;




char * buf =NULL;

buf = concatenate_strings((const char**)all_lines);


printf("buf = %s", buf);



fp=fopen("/sys/class/fw/rules/rules", "w");

fprintf(fp,"%s",buf);

fclose(fp);


  //return 0;
}



int show_rules(void) {

  FILE *fp;
  fp=fopen("./rules.txt", "r");
  long int lines =get_number_of_lines(fp);
  char * line = NULL;
  
    size_t len = 0;
    int i=0;
    int max=0;
    int bytesWritten=0;
    ssize_t read;
    

  

if(lines==-1){
return -1;
}

char *all_lines [lines+1];
fp=fopen("./rules.txt", "r");


  if (fp == NULL)
        exit(1);

    while ((read = getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %zu:\n", read);
        //max size of line

        if(read>max){
         max=read;
        }

        strcat(line,"\n");
        all_lines[i] = (char*)malloc(sizeof(char)*strlen(line));
        sprintf(all_lines[i],"%s",line);
        printf("%s", all_lines[i]);
        i++;
    }


all_lines[i] =NULL;




char * buf =NULL;

buf = concatenate_strings((const char**)all_lines);


printf("buf = %s", buf);



//fp=fopen("/sys/class/fw/rules/rules", "w");

//fprintf(fp,"%s",buf);

fclose(fp);


  return 0;
}


int clear_log(void)
{

  FILE *fp;

       fp=fopen("/sys/class/fw/log/reset", "w");

    if(fp == NULL)
    { perror("open failed"); return 0; }

   /**resetting log**/
fprintf(fp,"%d",0);

 

    fclose(fp);
    
    return 0;
}



int main(int argc,char * argv[]){

int i;

if (argc == 3 && strcmp(argv[1],"load_rules") == 0){
//printf("loading\n");
load_rules(argv[2]);
}
else if (argc == 2 && strcmp(argv[1],"show_rules") == 0)
show_rules();
else if (argc == 2 && strcmp(argv[1],"create_log") == 0){
for(i=0;i<BUFFER_LENGTH+1;i++)
create_line();
}
else if (argc == 2 && strcmp(argv[1],"clear_log") == 0)
clear_log();



return 0;
}

