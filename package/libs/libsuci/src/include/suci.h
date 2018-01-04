#ifndef _SUCI_H_
#define _SUCI_H_
#include <stdbool.h>
#include "uthash.h"

typedef struct kv_node suci_kvn_t;
struct kv_node
{
	char *key;
	char *value;
	suci_kvn_t *next;
	suci_kvn_t *prev;
};

typedef struct{
	suci_kvn_t *head;
	int len;
}suci_kvl_t;

typedef struct suci_hash{
	char *key;
	char *value;
	UT_hash_handle hh;
}suci_hash_t;

int do_uci_set(char *option, char *value);
int do_uci_get(char *option, char *value);
int do_uci_add_list(char *option, char *value);
int do_uci_del_list(char *option, char *value);
int do_uci_commit(char *package);
int do_uci_add(char *file_name, char *section, char *name);
int do_uci_delete(char *option, char *value);
int do_uci_rename(char *option, char *name);
int do_uci_get_dlm(char *option, char *value, char *delim);
int do_uci_add_pos(char *option, char *section, char *name, int pos);
int uci_del_section_bytype(char *file_name, char *section_type, int max_elem_num);

bool suci_kvl_init(suci_kvl_t *l);
void suci_kvl_insert(suci_kvl_t *l, suci_kvn_t *n);
void suci_kvl_add(suci_kvl_t *l, suci_kvn_t *n);
void suci_kvl_del(suci_kvl_t *l);
void suci_kvl_load_option(suci_kvl_t *l, struct uci_option *o);
void suci_kvl_load_section(suci_kvl_t *l, struct uci_section *s);
void suci_kvl_load_package(suci_kvl_t *l, struct uci_package *p);
suci_kvl_t * suci_kvl_create(char *tuple);
void suci_kvl_destroy(suci_kvl_t *l);
void suci_kvl_show(suci_kvl_t *l);
#define suci_kvl_for_each(_list, _node)	\
	for(_node = (_list)->head->next; 	\
		_node != (_list->head);		\
		_node = _node->next)

suci_kvl_t *suci_get_section_names(char *package, char *section_type);

void suci_hash_add_kv(suci_hash_t **kvs, char *key, char *value);
suci_hash_t *suci_hash_find_kv(suci_hash_t *kvs, char *key);
void suci_hash_free_kv(suci_hash_t *kv);
void suci_hash_delete_kv(suci_hash_t *kvs, suci_hash_t *kv);
void suci_hash_delete_all(suci_hash_t *kvs);
void suci_hash_sort_by_value(suci_hash_t *kvs);
void suci_hash_sort_by_key(suci_hash_t *kvs);
void suci_hash_load_kvl(suci_hash_t **kvs, suci_kvl_t *l);
suci_hash_t *suci_hash_create(char *tuple);
int suci_hash_get(suci_hash_t *kvs, char *key, char *value);
void suci_hash_destroy(suci_hash_t *kvs);
void suci_hash_show(suci_hash_t *kvs);
int suci_hash_performance_test(char *package);

#endif

