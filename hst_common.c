#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "basic.h"
#include "cJSON.h"
//#include "hst_list.h"
#include "hst_common.h"


static void hst_download_success_handle(char *resource_store_filepath, HST_NODE *resource)
{
    int len = 0;
    char cmd_buf[HST_COMMON_MSG_LEN] = {0};
    char cmd_path[HST_RESOURCE_PATH_LEN] = {0};

    if (!strncmp("acuupgrade", resource->node.file_type, strlen("acuupgrade")))
    {
        snprintf(cmd_buf, sizeof(cmd_buf), "echo %s > %s",
                                              resource->node.file_name,
                                              HST_ACU_UPGRADE_NAME);
        system(cmd_buf);
        system("/usr/sbin/acu_cmd_report -t 3"); 

    }
    else if (!strncmp("telupgrade", resource->node.file_type, strlen("telupgrade")))
    {
        len = strlen(resource_store_filepath) - strlen(resource->node.file_name);
        memcpy(cmd_path, resource_store_filepath, len); 
        snprintf(cmd_buf, sizeof(cmd_buf), "tar -xzf %s -C %s",
                                              resource_store_filepath,
                                              cmd_path);
        system(cmd_buf);
        unlink(resource_store_filepath);                                                        
    }

    return;
}

static int hst_get_result_from_shell(const char *cmd, char *result_buf, int buf_len)
{
    FILE *stream = NULL;
    stream = popen(cmd, "r");
    if (NULL == stream) 
    {
    	syslog(LOG_DEBUG, "%s popen error .....", __FUNCTION__);
        return 0;
    }
	if(NULL != fgets(result_buf, buf_len, stream))
    {
    	pclose(stream);
    	return 1;
    }
    else
    {
		pclose(stream);
		syslog(LOG_DEBUG, "%s run fgets error, error info is %s !", __FUNCTION__, strerror(errno));
    	return 0;
    }
}

static int hst_list_find(HST_NODE *hst_node, struct list_head *head)
{
	struct list_head *pos = NULL;
	HST_NODE *tmp = NULL;
	list_for_each(pos, head)
	{
		tmp = list_entry(pos, HST_NODE, list);
		if(tmp->node.url_len == hst_node->node.url_len)
		{
			if (0 == memcmp(tmp->node.url, hst_node->node.url, hst_node->node.url_len))
			{
				syslog(LOG_DEBUG, "%s this url has been configed, url is %s", __FUNCTION__, 
								hst_node->node.url);
				return 1;
			}
		}
	}
	syslog(LOG_DEBUG, "%s not find the same url !", __FUNCTION__);
	return 0;
}

static int hst_list_add(HST_NODE *hst_node, struct list_head *head)
{
	if(!hst_list_find(hst_node, head))
	{
		list_add(&(hst_node->list),head);
	}
	return 0;
}

static int hst_list_print_free(struct list_head *head)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	HST_NODE *tmp = NULL;
	int i = 0;
	
	list_for_each_safe(pos, next, head)
	{
		tmp = list_entry(pos, HST_NODE, list);
		if(tmp)
		{
			free(tmp->node.url);
			free(tmp);
		}
	}
	return 0;
}

static int hst_dealwith_urls(cJSON *url_arrary, struct list_head *head)
{
	cJSON *url_info = NULL;
	int count_urls = 0;
	unsigned int file_size = 0;
	cJSON *iterm_url = NULL;
	cJSON *iterm_filename = NULL;
	cJSON *iterm_filetype = NULL;
	cJSON *iterm_md5 = NULL;

	int count = 0;
	
	count_urls = cJSON_GetArraySize(url_arrary);
	//syslog(LOG_DEBUG, "%s get urls's count is %d", __FUNCTION__, count_urls);
	url_info = url_arrary->child;
	while(NULL != url_info)
	{
		count ++;
		HST_NODE *resource_node = NULL;
		if(NULL == (resource_node = (HST_NODE *)malloc(sizeof(HST_NODE))))
		{
			syslog(LOG_DEBUG, "%s has not memory for use !", __FUNCTION__);
			return -1;
		}

		memset(resource_node, 0, sizeof(HST_NODE));
		
		if(NULL == (iterm_filename = cJSON_GetObjectItem(url_info, "file_name")))
		{
			syslog(LOG_DEBUG, "%s get iterm of file_name error !", __FUNCTION__);
			free(resource_node);
			return -1;
		}		
		if(NULL == (iterm_filetype = cJSON_GetObjectItem(url_info, "file_type")))
		{
			syslog(LOG_DEBUG, "%s get iterm of file_type error !", __FUNCTION__);
			free(resource_node);
			return -1;
		}
		if(NULL == (iterm_md5 = cJSON_GetObjectItem(url_info, "md5")))
		{
			syslog(LOG_DEBUG, "%s get iterm of md5 error !", __FUNCTION__);
			free(resource_node);
			return -1;
		}
		if(NULL == (iterm_url = cJSON_GetObjectItem(url_info, "url")))
		{
			syslog(LOG_DEBUG, "%s get iterm of url error !", __FUNCTION__);
			free(resource_node);
			return -1;
		}
		if(NULL == (resource_node->node.url = 
				(unsigned char *)malloc(strlen(iterm_url->valuestring)+1)))
		{
			syslog(LOG_DEBUG, "%s has not memory for store tmp_url !", __FUNCTION__);
			free(resource_node);
			return -1;
		}
		
		//printf("Malloc resource_node->node.url's addr = %p\n", resource_node->node.url);
		
		memset(resource_node->node.url, 0, strlen(iterm_url->valuestring)+1);
		
		resource_node->node.url_len = strlen(iterm_url->valuestring);
		//syslog(LOG_DEBUG, "url len = %d", resource_node->node.url_len);

		strncpy(resource_node->node.file_name, iterm_filename->valuestring,
								strlen(iterm_filename->valuestring));
		syslog(LOG_DEBUG, "parse info, file_name=%s", resource_node->node.file_name);

		strncpy(resource_node->node.file_type, iterm_filetype->valuestring, 
								strlen(iterm_filetype->valuestring));
		syslog(LOG_DEBUG, "file_type=%s", resource_node->node.file_type);

		strncpy(resource_node->node.md5, iterm_md5->valuestring,
								strlen(iterm_md5->valuestring) + 1);				
		strncpy(resource_node->node.url, iterm_url->valuestring, 
								strlen(iterm_url->valuestring) + 1);
		syslog(LOG_DEBUG, "parse info, url=%s",	resource_node->node.url);
		resource_node->node.flag_downloadok = HST_HASNOT_DOWNLOAD;
		/* add this node to list */
		hst_list_add(resource_node, head);
		url_info = url_info->next;
		syslog(LOG_DEBUG, "The count = %d", count);
	}
	return 0;
}

int hst_resource_parse(const char *json_resource, struct list_head *head)
{
	cJSON *root = NULL;
	cJSON *url_arrary = NULL;
	//syslog(LOG_DEBUG, "The json_resource is %s", json_resource);
	/* parse root */
	if(NULL == (root = cJSON_Parse(json_resource)))
	{
		syslog(LOG_DEBUG, "%s parse root error !", __FUNCTION__);
		return -1;
	}
	/* getting urls */
	if(NULL == (url_arrary = cJSON_GetObjectItem(root, "urls")))
	{
		syslog(LOG_DEBUG, "%s parse json of urls error !", __FUNCTION__);
		return -1;
	}
	
	/* deal with urls */
	if(0 > hst_dealwith_urls(url_arrary, head))
	{
		syslog(LOG_DEBUG, "%s deal with urls error !", __FUNCTION__);
		return -1;
	}
	return 0;
}

int hst_get_file_modifyed_time(char *path, unsigned int *done_time)
{
	unsigned int geted_size = 0;
	struct stat statbuff;
	
	if(stat(path, &statbuff) < 0 )
	{
		syslog(LOG_DEBUG, "%s run stat error, err info: %s , path=%s!", 
									__FUNCTION__, strerror(errno),path);
		*done_time = 0;
		return 0;
	}
	else
	{
		*done_time = (unsigned int)statbuff.st_mtime;
		return 1;
	}	
}

int hst_get_iosapp_store_name(char *resource_path, HST_NODE *resource)
{
	char *pos_begin = NULL, *pos_end = NULL;
	if((NULL == (pos_begin = strstr(resource->node.url, HST_APPLE_FIXED_FIELD))) || 
		(NULL == (pos_end = strstr(resource->node.url, "?"))))
	{
		syslog(LOG_DEBUG, "This url: %s is not for ios app !", resource->node.url);
		return 0;
	}
	else
	{
		memcpy(resource_path, pos_begin + sizeof(HST_APPLE_FIXED_FIELD), 
				pos_end - (pos_begin + sizeof(HST_APPLE_FIXED_FIELD)));
		syslog(LOG_DEBUG, "From this url, get ios app store path is %s", 
														resource_path);
		return 1;
	}
}

#if 0 
int hst_check_file_size(char *path, unsigned int resource_size)
{
	unsigned int geted_size = 0;
	struct stat statbuff;
	
	if(stat(path, &statbuff) < 0 )
	{
		syslog(LOG_DEBUG, "%s run stat error, err info: %s , path=%s!", 
									__FUNCTION__, strerror(errno),path);
		return 0;
	}
	else
	{
		geted_size = statbuff.st_size;
	}
	
	if(resource_size != geted_size)
	{
		syslog(LOG_DEBUG, "%s, download file size is error, get file size is %d, "
							"correct is %d", __FUNCTION__, geted_size, resource_size);
		return 0;
	}
	else
	{
		syslog(LOG_DEBUG,"check file size is ok !");
		return 1;
	}
}
#endif

int hst_check_file_md5(char *path, unsigned char *resource_md5)
{
	FILE *stream = NULL;
	char cmd_md5sum[HST_RESOURCE_PATH_LEN] = {0};
	char tmp_md5[HST_COMMON_MSG_LEN] = {0};
	snprintf(cmd_md5sum, sizeof(cmd_md5sum), "/usr/bin/md5sum %s", path);
	if(!strncmp(resource_md5, "N", 1))
	{
		syslog(LOG_DEBUG, "In %s, this url do not check md5 !", __FUNCTION__);
		return 1;
	}
	if((!hst_get_result_from_shell(cmd_md5sum, tmp_md5, sizeof(tmp_md5))) ||
		(32 > strlen(tmp_md5)))
	{
		syslog(LOG_DEBUG, "%s run error !");
		return 0;
	}
	if(!strncasecmp(resource_md5, tmp_md5, 32))
	{
		syslog(LOG_DEBUG,"%s check resource md5 success, file's md5: %s, config's md5 : %s!",
			__FUNCTION__, tmp_md5, resource_md5);
		return 1;
	}
	else
	{
		syslog(LOG_DEBUG, "%s check resource md5 fail, file's md5: %s, config's md5 : %s!",
			__FUNCTION__, tmp_md5, resource_md5);
		return 0;
	}
#if 0
	snprintf(cmd_md5sum, sizeof(cmd_md5sum), "echo -n \"\" > %s && /usr/bin/md5sum %s > %s", 
											HST_FILE_MD5_TMP, path, HST_FILE_MD5_TMP);
	syslog(LOG_DEBUG, "%s run cmd : %s", __FUNCTION__, cmd_md5sum);
	system(cmd_md5sum);

    stream = fopen(HST_FILE_MD5_TMP, "r");
    if (NULL == stream) 
    {
    	syslog(LOG_DEBUG, "%s open error, error infi: %s", __FUNCTION__, strerror(errno));
        return 0;
    }
	if((!fgets(tmp_md5, sizeof(tmp_md5), stream)) && (32 < strlen(tmp_md5)))
    {
    	fclose(stream);
		syslog(LOG_DEBUG, "%s run fgets error, error info is %s !", __FUNCTION__, strerror(errno));
    	return 0;
    }
    else
    {
    	fclose(stream);
		if(!strncmp(resource_md5, tmp_md5, 32))
		{
			syslog(LOG_DEBUG,"%s check resource md5 success, file's md5: %s, config's md5 : %s!",
				__FUNCTION__, tmp_md5, resource_md5);
			return 1;
		}
		else
		{
			syslog(LOG_DEBUG, "%s check resource md5 fail, file's md5: %s, config's md5 : %s!",
				__FUNCTION__, tmp_md5, resource_md5);
			return 0;
		}
    }
#endif

}

void hst_rm_file(char *resource_path)
{
	unsigned char command_rf[HST_COMMON_MSG_LEN] = {0};
	snprintf(command_rf, sizeof(command_rf), "rm -rf %s", resource_path);
	system(command_rf);
	syslog(LOG_DEBUG, "file is error, so delete the file:%s !", resource_path);
	return;
}

int hst_check_download_isok(char *resource_path, HST_NODE *resource)
{
	if(access(resource_path, F_OK))
	{
		syslog(LOG_DEBUG, "%s access %s fail, this file is not exist !", __FUNCTION__, resource_path);
		return 0;
	}
	if(!hst_check_file_md5(resource_path, resource->node.md5))
	{
		hst_rm_file(resource_path);
		return 0;
	}
	else
	{
		syslog(LOG_DEBUG, "%s run success !", __FUNCTION__);
		return 1;
	}
}

int hst_create_store_info(char *resource_store_filepath, HST_NODE *tmp_node, 
								int resource_store_filepath_len)
{
	unsigned char pri_cmd[] = "wget --passive-ftp -t 3 -T 180 -c -O ";
	char buff_tmp[HST_RESOURCE_PATH_LEN] = {0};
	char sdcard_path[HST_RESOURCE_PATH_LEN] = {0};
	char resource_store_dirpath[HST_RESOURCE_PATH_LEN] = {0};
	char *cpos = NULL;
	int resource_path_len = 0;
	int mem_size = 0;
	get_hst_sdcard_path(sdcard_path, sizeof(sdcard_path));
	if (!strlen(sdcard_path))
	{
		syslog(LOG_DEBUG, "%s get adcard path error !", __FUNCTION__);  
		return -1;
	}
	
	if((strlen("app") == strlen(tmp_node->node.file_type)) &&
		(!strncmp("app", tmp_node->node.file_type, strlen("app"))))
	{
		if(hst_get_iosapp_store_name(buff_tmp, tmp_node))
		{
			if(NULL != (cpos = strrchr(buff_tmp, '/')))
			{
				memcpy(resource_store_dirpath, buff_tmp, cpos - buff_tmp);
				//printf("Get ios app dir is %s\n", resource_store_dirpath);
			}
			
			resource_path_len = snprintf(resource_store_filepath, 
													resource_store_filepath_len, 
													"%s%s/%s",
													sdcard_path,
													HST_IOSAPP_PATH,
													buff_tmp);
			/* create dir */
			memset(buff_tmp, 0, sizeof(buff_tmp));
			snprintf(buff_tmp, sizeof(buff_tmp), "mkdir -p %s%s/%s", 
									sdcard_path, HST_IOSAPP_PATH, resource_store_dirpath);
								
		}
		else
		{	
			/* Create dir */
			memset(buff_tmp, 0, sizeof(buff_tmp));
			snprintf(buff_tmp, sizeof(buff_tmp), "mkdir -p %s%s", 
									sdcard_path, HST_ANDROIDAPP_PATH);
			resource_path_len = snprintf(resource_store_filepath, 
													resource_store_filepath_len, 
													"%s%s/%s",
													sdcard_path,
													HST_ANDROIDAPP_PATH,
													HST_ANDROIDAPP_NAME);
		}
	}
	else if((strlen("portal") == strlen(tmp_node->node.file_type)) &&
			(!strncmp("portal", tmp_node->node.file_type, strlen("portal"))))
	{
		memset(buff_tmp, 0, sizeof(buff_tmp));
		snprintf(buff_tmp, sizeof(buff_tmp), "mkdir -p %s%s", 
								sdcard_path, HST_PORTAL_PATH);
		resource_path_len = snprintf(resource_store_filepath, 
													resource_store_filepath_len, 
													"%s%s/%s",
													sdcard_path,
													HST_PORTAL_PATH,
													HST_PORTAL_NAME);
	}
	else 
	{
		memset(buff_tmp, 0, sizeof(buff_tmp));
		snprintf(buff_tmp, sizeof(buff_tmp), "mkdir -p %s/%s/%s", 
								sdcard_path, HST_DIR_NAME, tmp_node->node.file_type);
		resource_path_len = snprintf(resource_store_filepath, 
													resource_store_filepath_len, 
													"%s/%s/%s/%s",
													sdcard_path,
													HST_DIR_NAME,
													tmp_node->node.file_type,
													tmp_node->node.file_name);
	}
	/* Create dir */
	system(buff_tmp);	
	/* get malloc szie */
	mem_size = sizeof(pri_cmd) + resource_path_len;
	mem_size += tmp_node->node.url_len;
	mem_size += sizeof(HST_RESOURCE_BACKUP_NAME);
	mem_size += 4; 
	return mem_size;
}

int hst_resource_download(struct list_head *head)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct timeval crrent_time = {0};
	HST_NODE *tmp_node = NULL;
	unsigned char *download_cmd = NULL;
	unsigned char pri_cmd[] = "wget --passive-ftp -t 1 -T 60 -c -O ";
	unsigned char download_status[] = {'0', '1', '2'};/*0:success, 1:eror, 2:don't download*/
	int mem_size = 0;
	int ret = 0, flag_download = 0;
	int flag_urlis_ios = 0;
	if(list_empty(head))
	{
		syslog(LOG_DEBUG, "%s, the list is empty !", __FUNCTION__);
		return 0;
	}
	list_for_each_safe(pos, next, head)
	{
		tmp_node = list_entry(pos, HST_NODE, list);
		if((HST_HASNOT_DOWNLOAD == tmp_node->node.flag_downloadok) && (0 < tmp_node->node.url_len))
		{
			char resource_store_filepath[HST_RESOURCE_PATH_LEN] = {0};
			char cmd_movefile[HST_RESOURCE_PATH_LEN * 2 ] = {0};
			if(0 > (mem_size = hst_create_store_info(resource_store_filepath, tmp_node, 
													sizeof(resource_store_filepath))))
			{
				continue;
			}
			
			//printf("resource_store_filepath = %s\n", resource_store_filepath);
			
			if(hst_check_download_isok(resource_store_filepath, tmp_node))
			{
				strncpy(tmp_node->node.download_status, "2", 1);
				gettimeofday(&crrent_time, NULL);
	            tmp_node->node.done_time = crrent_time.tv_sec;
				syslog(LOG_DEBUG, "This file has been downloaded, file is %s", 
													tmp_node->node.file_name);
			}
			else
			{	
				char backup_resource_filepath[HST_RESOURCE_PATH_LEN] = {0};
				download_cmd = (unsigned char *)malloc(mem_size);
				if(NULL == download_cmd)
				{
					syslog(LOG_DEBUG, "%s get memory error !", __FUNCTION__);
					continue;
				}
				
				memset(download_cmd, 0, mem_size);
				snprintf(download_cmd, mem_size, "%s %s%s %s", 
												pri_cmd, 
												resource_store_filepath, 
												HST_RESOURCE_BACKUP_NAME,
												tmp_node->node.url);
				snprintf(backup_resource_filepath, sizeof(backup_resource_filepath), 
												"%s%s",
												resource_store_filepath,
												HST_RESOURCE_BACKUP_NAME);
				
				ret = system(download_cmd);	
				gettimeofday(&crrent_time, NULL);
            	tmp_node->node.done_time = crrent_time.tv_sec;
				
				if(0 != ret)
				{
					syslog(LOG_DEBUG, "%s get download url %s error !",  __FUNCTION__, download_cmd);
					flag_download = -1;
					strncpy(tmp_node->node.download_status, "1", 1);
					hst_rm_file(backup_resource_filepath);
				}
				else
				{	
					if(hst_check_download_isok(backup_resource_filepath, tmp_node))
					{	
						strncpy(tmp_node->node.download_status, "0", 1);
						tmp_node->node.flag_downloadok = HST_HASBEEN_DOWNLOAD;
					    snprintf(cmd_movefile, sizeof(cmd_movefile), "mv %s %s",
																backup_resource_filepath,
																resource_store_filepath);
					    system(cmd_movefile);
					    system("/bin/sync");
					    hst_download_success_handle(resource_store_filepath, tmp_node);
					}
					else
					{
						strncpy(tmp_node->node.download_status, "1", 1);
						flag_download = -1;
					}
					//syslog(LOG_DEBUG, "mv cmd is %s", cmd_movefile);
				}
				/* release memory */
				free(download_cmd);
			}
		}
	}
	return flag_download;
}

void hst_free_list(struct list_head *head)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	HST_NODE *tmp = NULL;
	list_for_each_safe(pos, next, head)
	{
		tmp = list_entry(pos, HST_NODE, list);
		free(tmp->node.url);
		free(tmp);
		tmp = NULL;
	}
}

/*
** write json data to file, then cm read it and send it to sg 
*/
int hst_resource_report(struct list_head *head)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	HST_NODE *tmp = NULL;
	cJSON *root = NULL, *urls = NULL, *urlinfo = NULL;
	char *msg = NULL;
	char apmac[32] = {0};
	int ret = 0, sleep_time = 0;
	if(!hst_get_result_from_shell("/usr/sbin/show_ap MAC_ADDRESS", apmac, sizeof(apmac)))
	{
		syslog(LOG_ERR, "%s get ap mac error !", __FUNCTION__);
		return -1;		
	}
	else
	{
		if((strlen(apmac) != 0) && (apmac[strlen(apmac) - 1] == '\n'))
			apmac[strlen(apmac) - 1] = '\0';
	}
	if(NULL == (root = cJSON_CreateObject()))
	{
		syslog(LOG_DEBUG, "%s create json roor eroor !", __FUNCTION__);
		return -1;
	}
	if(NULL == (urls = cJSON_CreateArray()))
	{
		syslog(LOG_DEBUG, "%s create json array error !", __FUNCTION__);
		return -1;
	}

	cJSON_AddItemToObject(root, "urls", urls);
	list_for_each_safe(pos, next, head)
	{
		tmp = list_entry(pos, HST_NODE, list);
		if(tmp)
		{
			cJSON_AddItemToArray(urls, urlinfo = cJSON_CreateObject());
			if(urlinfo)
			{
				cJSON_AddStringToObject(urlinfo, "url", tmp->node.url);
				cJSON_AddStringToObject(urlinfo, "status", tmp->node.download_status);
				cJSON_AddNumberToObject(urlinfo, "time", tmp->node.done_time);
				cJSON_AddStringToObject(urlinfo, "ap_mac", apmac);
			}
			else
			{
				syslog(LOG_DEBUG, "%s create object error !", __FUNCTION__);
			}
		}
	}	
	msg = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    while(1)
    {
		/* File is not exist */
	    if(0 > access(HST_RESOURCE_JSON_FILE, F_OK))
	    {
			if (!freopen(HST_RESOURCE_JSON_FILE, "w+", stdout)) 
			{
				syslog(LOG_DEBUG, "[%s] freopen error, strerr is %s", __FUNCTION__, strerror(errno));
				free(msg);
				ret = -1;
				break;
			}
			/* print msg to file */
			printf("%s", msg);
			fclose(stdout);
			ret = 0;
			break;
	    }
	    else
	    {
			srand((unsigned)time(NULL));
			sleep_time = rand() % 5 + 1;
			syslog(LOG_DEBUG, "The file: %s is exist, so retry after %d s !", 
								HST_RESOURCE_JSON_FILE, sleep_time);
			sleep(sleep_time);
	    }
    }
	return ret;
}

