#ifndef _HST_COMMON_H
#define _HST_COMMON_H

#include "hst_list.h"

#define HST_URL_LEN 512
#define HST_RESOURCE_PATH_LEN 256
#define HST_FILE_TYPE_LEN 32
#define HST_MD5_LEN 64
#define HST_STATUS_LEN 4
#define HST_FILE_NAME_LEN 64
#define HST_CONUT_RETRY 5
#define HST_COMMON_MSG_LEN 256
#define HST_RESOURCE_JSON_FILE 		"/tmp/hst_resource.json"
//#define HST_APPLE_FIXED_FIELD 		"apple-assets-us-std-000001"
#define HST_APPLE_FIXED_FIELD 		"iosapps.itunes.apple.com"
#define HST_FILE_MD5_TMP 			"/tmp/hst_file_md5_tmp"
#define HST_DIR_NAME 				"haishangtong"
#define HST_ANDROIDAPP_NAME         "haishangtong.apk"
#define HST_ANDROIDAPP_PATH			"/haishangtong/app/android"
#define HST_IOSAPP_PATH				"/haishangtong/app/ios"
#define HST_PORTAL_PATH 			"/haishangtong/portal"
#define HST_PORTAL_NAME				"hst_download.html"
#define HST_RESOURCE_BACKUP_NAME    ".cloud"
#define HST_ACU_UPGRADE_NAME        "/etc/ap11n/config/acu_upgrade_name"
#define HST_SLEEP_TIME 10
enum
{
	HST_RESOURCE_DOWNLOAD_SUCCESS,
	HST_RESOURCE_DOWNLOAD_ERROR,
	HST_RESOURCE_IS_SAME
};

enum
{
	HST_HASNOT_DOWNLOAD,
	HST_HASBEEN_DOWNLOAD
};

typedef struct hst_resource
{
	unsigned char file_type[HST_FILE_TYPE_LEN];
	unsigned char file_name[HST_FILE_NAME_LEN];
	unsigned char md5[HST_MD5_LEN];
	unsigned char download_status[HST_STATUS_LEN];
	unsigned int flag_downloadok;
	unsigned int done_time;
	unsigned int url_len;
	unsigned char *url;
}__attribute__((packed))HST_RESOURCE_INFO;

typedef struct hst_node
{
	struct list_head list;
	HST_RESOURCE_INFO node;
}HST_NODE;

int hst_resource_parse(const char *json_resource, struct list_head *head);
int hst_resource_download(struct list_head *head);

#endif /*_HST_COMMON_H*/
