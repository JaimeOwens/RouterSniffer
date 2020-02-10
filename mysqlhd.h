#include<stdio.h>
#include<mysql/mysql.h>   
#include<string.h>
#include<stdlib.h>
 
MYSQL *conn_prt;    
MYSQL_RES *res;
MYSQL_ROW row;
 
char select_head[50] = "select * from ";
char desc_head[50] = "desc ";
char insert_head[200] = "insert into ";
char drop_msg_head[50] = "delete from ";
char change_base_head[50] = "use ";
  
/*连接mysql数据库*/
void self_connect(MYSQL *conn_prt)
{
	conn_prt = mysql_init(NULL);
	if(!mysql_real_connect(conn_prt,"localhost","root",
		"","n161002110",0,NULL,0))
	{
		printf("failed to connect:%s\n",mysql_error(conn_prt));
		exit(0) ;
	}
	printf("connect success!\n");
}
  
/*往某个表中插入数据*/
void insert_msg(char *table_name,char *field,char *message)
{
	int t;
	char insert_head[30]="insert into";
	char insert_query[200];
	char left[5]="(";
	char right[5]=")";
	char values[50]="values";
 
	MYSQL conn_ptr;
	mysql_init(&conn_ptr);
	if(!mysql_real_connect(&conn_ptr,"localhost","root",
		"","n161002110",0,NULL,0))
	{
		printf("failed to connect:%s\n",mysql_error(&conn_ptr));
		exit(0) ;
	}
	
	strcpy(insert_query,insert_head);   //insert into
	/*把几个变量字符串连接成一个完整的mysql命令*/
	sprintf(insert_query,"%s %s %s%s%s %s %s%s%s",insert_head,table_name,left,field,right,values,left,message,right);
	printf("insert_query:%s\n",insert_query);
 
	t = mysql_query(&conn_ptr,insert_query);
	if(t)
	{
		printf("failed to query:%s\n",mysql_error(&conn_ptr));
		return;
	}
	printf("OK\n");
	mysql_close(&conn_ptr);
	return;
}
 
void get_id(char *id){
	MYSQL conn_ptr;
	mysql_init(&conn_ptr);
	if(!mysql_real_connect(&conn_ptr,"localhost","root",
		"","n161002110",0,NULL,0))
	{
		printf("failed to connect:%s\n",mysql_error(&conn_ptr));
		exit(0) ;
	}
	
	int t;
	t = mysql_query(&conn_ptr,"select id+1 from http_info order by id desc limit 1");
	if(t)
	{
		printf("failed to query:%s\n",mysql_error(&conn_ptr));
		return;
	}
	res = mysql_store_result(&conn_ptr);
	if(mysql_num_rows(res)){
		while((row=mysql_fetch_row(res))){
			printf("row:%s\n",row[0]);
			strcpy(id,row[0]);
		}
	}
	else{
		strcpy(id,"1");
	}
	mysql_free_result(res);
	mysql_close(&conn_ptr);
	return;
}
