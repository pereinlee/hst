/*
** Job: for resource download
** Author: chengdaqiang
** Time: 2018.3.2
*/
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "hst_common.h"

struct list_head *g_head = NULL;

int main(const int argc, const char **argv)			//海上通资源下载
{
	int ret = -1;
	int conut_retry = HST_CONUT_RETRY;
	openlog("HST_RESOURCE", LOG_ODELAY, 0);
	if(2 != argc)
	{
		syslog(LOG_DEBUG, "argc error !");
		closelog();
		return -1;
	}
	/* Init list head */
	g_head = malloc(sizeof(struct list_head));
	if(NULL == g_head)
	{
		syslog(LOG_DEBUG, "g_head is NULL !");
		return -1;
	}
	INIT_LIST_HEAD(g_head);

	if(0 > (ret = hst_resource_parse(argv[1], g_head)))
	{
		syslog(LOG_DEBUG, "resource parse error !");
		closelog();
		return -1;
	}
	while(0 < conut_retry)
	{
		if(0 > hst_resource_download(g_head))
		{
			conut_retry --;
			sleep(HST_SLEEP_TIME);
		}
		else
		{
			conut_retry = 0;
		}
	}
	
	conut_retry = HST_CONUT_RETRY;
	while(0 < conut_retry)
	{
		if(0 > hst_resource_report(g_head))
		{
			conut_retry --;
			syslog(LOG_DEBUG, "assemble json to file error !");
			sleep(HST_SLEEP_TIME);
		}
		else
		{
			conut_retry = 0;
		}
	}	
	hst_free_list(g_head);
	free(g_head);
    syslog(LOG_DEBUG, "Hst resource download quit normally, conut_retry:%d!", conut_retry);
	closelog();
	return 0;
}


