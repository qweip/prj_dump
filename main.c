#define _WIN32_WINNT 0x0500
#define HAVE_REMOTE
#include "pcap.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#define LogFile "W32Local.log"
#define IniFile "W32Local.ini"
static int g_intDebug;

void trimNewline(char *str) {
	char *p;
	p = strchr(str, '\n'); if(p) *p = '\0';
	p = strchr(str, '\r'); if(p) *p = '\0';
}

void Write_File(const char *Msg ,const char *f ,int state )
{
    if(g_intDebug==1)
    {
        FILE *pf='\0';
        if(state==1)//�N���e�����M��
        {
            pf=fopen(f,"w");
            fprintf(pf,Msg);
        }
        else//������e�����A�~����
        {
            pf=fopen(f,"a");
            fprintf(pf,Msg);
        	fprintf(pf, "\n");
        }
        
        fclose(pf);
    }
}


char* Readini(const char *filename)
{
	size_t len;
	char buf[255],buf1[65535];
	char *str;
	FILE * f = fopen(filename, "r");
	if (f) len = _filelength(_fileno(f));
    if(!len) return;
    
    while(fgets(buf,sizeof(buf),f)!=NULL){	
		strcat(buf1,buf);
	}
	if(ferror(f)){
		//fprintf(stderr,"Unable to read the file %s!",f);
		sprintf(buf,"Unable to read the file %s!",f);
		Write_File(buf,LogFile,0); 
		exit(-1);
	}
	char *loc=strstr(buf1,"DeviceName=");
	if(!loc) return 0;
	str = strdup(loc + 11);
	return str;
    
}

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    pcap_dump(dumpfile, header, pkt_data);
    struct tm * timeinfo;
}

char* timenow(){
	time_t rawtime;
	static char timestr[30];
	struct tm * timeinfo;
	time (&rawtime);
  	timeinfo = localtime (&rawtime);
  	strftime (timestr,30,"[%Y/%m/%d %H:%M:%S]",timeinfo);
  	return timestr;
}

char* strcatv2(char *buf,int len, ...){
	
	memcpy(buf, "", 1);
	va_list args;
    va_start(args, len);
	int j;
    for(j = 0; j < len; j++) {
        strcat(buf,va_arg(args, char*));
    }
    va_end(args);
    return buf;
}

main(int argc, char **argv)
{
	FILE *f=0;
	//HWND hWnd = GetConsoleWindow(); //���õ���1
	//ShowWindow( hWnd, SW_HIDE ); //���õ���2
	pcap_if_t *alldevs;
	pcap_if_t *d;	
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;
	int i=0;
	char buf[255];
	char errbuf[PCAP_ERRBUF_SIZE];
	f=fopen(LogFile,"r");
	g_intDebug=1;

	while(!f){
		Write_File(strcatv2(buf ,8 ,timenow() ,"[Error]Uable to open the file " ,LogFile ,"!\n" 
							,timenow() ,"[Message]Establish the data " ,LogFile ,"..." ),LogFile,1);//sprintf or snprintf�i�H��{ 
		break;
	}
	fclose(f);
	
	f=fopen(IniFile,"r");
	while(!f){
		Write_File(strcatv2(buf ,9 ,"\n",timenow() ,"[Error]Uable to open the file " ,IniFile ,"!\n" 
							,timenow() ,"[Message]Establish the data " ,IniFile ,"..." ),LogFile,0);//sprintf or snprintf�i�H��{ 
		Write_File("DeviceName=",IniFile,1);
		break;
	}
	fclose(f);
	
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        Write_File(strcatv2(buf,3,timenow(),"[Error]Error in pcap_findalldevs:",errbuf),LogFile,0);
        return -1;
    }
    
    char *res = Readini(IniFile);
    trimNewline(res);
    if(!res){
    	Write_File(strcatv2(buf,2,timenow(),"[Error]Argv[1] cannot be NULL"),LogFile,0);
        return -1;
	}
	
	
    Write_File(strcatv2(buf,3,timenow(),"[Message]Get DeviceName :",res),LogFile,0);
    
    
    for(d=alldevs; d; d=d->next)
    { 	 
        if (strcmp(d->name,res)==0)
        {
        	i=1;
            break;
		} 
		else{
			i=0;
		}
    }
    if(i==0){
    	Write_File(strcatv2(buf,3,timenow(),"[Error]No Interface Name: ",res),LogFile,0);
    	return -1;
	}
	
    Write_File(strcatv2(buf,5,timenow(),"[Message]Description: ",d->description," Name: ",d->name),LogFile,0);
    
    if ((adhandle= pcap_open(d->name, 65536 ,PCAP_OPENFLAG_PROMISCUOUS ,
							1000 ,NULL ,errbuf ) ) == NULL)
    {
        
    	Write_File(strcatv2(buf,4,timenow(),"[Error]Unable to open the adapter. " ,
							d->name ," is not supported by WinPcap"),LogFile,0);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    time_t rawtime;
	char timestr[30];
  	struct tm * timeinfo; 
  	time (&rawtime);
  	timeinfo = localtime (&rawtime);
  	strftime (timestr,30,"[%Y-%m-%d_%H(h)%M(m)%S(s)]",timeinfo);
	dumpfile = pcap_dump_open(adhandle,timestr);
	
	Write_File(strcatv2(buf ,4 ,timenow(),"[Message]",d->description," Create!") ,LogFile ,0);
	
    if(dumpfile==NULL)
    {
        Write_File(strcatv2(buf ,3 ,timenow(),"[Error]Error opening output file") ,LogFile ,0);
        return -1;
    }
    
	Write_File(strcatv2(buf ,6 ,timenow() ,"[Message]istening on (" ,d->description ,")filename (",timestr,")..."),LogFile,0);
    //���ɦW.pcap 
    pcap_freealldevs(alldevs);
    pcap_loop(adhandle ,0 ,packet_handler ,(unsigned char *)dumpfile);
	
    return 0;
}



