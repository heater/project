#include <uci.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "uthash.h"
#include "suci.h"

int do_uci_commit(char *package);

static const char *delimiter = " ";


static void uci_print_value(char *output, const char *v)
{

	while (*v) {
		if (*v != '\'')
			*output = *v;
		else
			sprintf(output, "'\\''");
		v++;
		output++;
	}
}

static void uci_show_value(struct uci_option *o, char *value, bool quote)
{
	struct uci_element *e;
	bool sep = false;
	char *space;
	char *p = value;

	switch(o->type) {
	case UCI_TYPE_STRING:
		if (quote)
			uci_print_value(value, o->v.string);
		else
			strcpy(value, o->v.string);
		break;
	case UCI_TYPE_LIST:
		uci_foreach_element(&o->v.list, e) {
			p += sprintf(p, "%s", (sep ? delimiter : ""));
//			printf("%s", (sep ? delimiter : ""));
			space = strpbrk(e->name, " \t\r\n");
			if (!space && !quote)
				p += sprintf(p, "%s", e->name);
//				printf("%s", e->name);
			else
				uci_print_value(value, e->name);
			sep = true;
		}
		break;
	default:
		p += sprintf(p, "<unknown>");
		break;
	}
}

int do_uci_set(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[2048];
	int ret = UCI_OK;

	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	sprintf(cmd, "%s=%s", option, value);

	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_set(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);

	if(ptr.value && !ptr.option && ptr.section && ptr.package) {
		ret = do_uci_commit(ptr.package);
	}
	return ret;

}

int do_uci_add_list(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;


	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	sprintf(cmd, "%s=%s", option, value);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_add_list(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;

}

int do_uci_del_list(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;


	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	sprintf(cmd, "%s=%s", option, value);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_del_list(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;

}

int do_uci_get(char *option, char *value)
{
	struct uci_element *e;
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;


	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	sprintf(cmd, "%s", option);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	if (ptr.value){
		uci_free_context(ctx);
		return -1;
	}

	e = ptr.last;

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
			ctx->err = UCI_ERR_NOTFOUND;
			uci_free_context(ctx);
			return -1;
	}
	switch(e->type) {
	case UCI_TYPE_SECTION:
		strcpy(value, ptr.s->type);
		break;
	case UCI_TYPE_OPTION:
		uci_show_value(ptr.o, value,false);
		break;
	default:
		break;
	}

	uci_free_context(ctx);
	return ret;

}

int do_uci_commit(char *package)
{
	struct uci_ptr ptr;
	int ret = -1;

	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	if (uci_lookup_ptr(ctx, &ptr, package, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}
	ret = uci_commit(ctx, &ptr.p, false);
	if(ret != UCI_OK) {
		goto out;
	}
out:
	if (ptr.p)
		uci_unload(ctx, ptr.p);
	uci_free_context(ctx);
	return ret;

}

int do_uci_add(char *option, char *section, char *name)
{
	struct uci_package *p = NULL;
	struct uci_section *s = NULL;
	int ret;

	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	if(option == NULL || section == NULL){
		uci_free_context(ctx);
		return -1;
	}

	ret = uci_load(ctx, option, &p);
	if (ret != UCI_OK)
		goto done;

	ret = uci_add_section(ctx, p, section, &s);
	if (ret != UCI_OK)
		goto done;

	ret = uci_save(ctx, p);

done:
	if (ret != UCI_OK){
		uci_free_context(ctx);
		return -1;
	}
	else if (s && name != NULL) {
		strcpy(name, s->e.name);
	}
	uci_free_context(ctx);

	ret = do_uci_commit(option);

	return ret;
}

int do_uci_delete(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK, dummy;


	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}



	if(value != NULL)
		sprintf(cmd, "%s=%s", option, value);
	else
		sprintf(cmd, "%s", option);

	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	if (ptr.value && !sscanf(ptr.value, "%d", &dummy)){
		uci_free_context(ctx);
		return -1;
	}
	ret = uci_delete(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;
}

int do_uci_rename(char *option, char *name)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;


	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	sprintf(cmd, "%s=%s", option, name);

	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_rename(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;

}

/*
*func_name:	uci_show_value_dlm
*func_dec:   	change the delimeter of the uci_show_value from " " to ":".
*/
static void uci_show_value_dlm(struct uci_option *o, char *value, bool quote, char *delim)
{
	struct uci_element *e;
	bool sep = false;
	char *space;
	char *p = value;

	switch(o->type) {
	case UCI_TYPE_STRING:
		if (quote)
			uci_print_value(value, o->v.string);
		else
			strcpy(value, o->v.string);
		break;
	case UCI_TYPE_LIST:
		uci_foreach_element(&o->v.list, e) {
			p += sprintf(p, "%s", (sep ? delim : ""));
			space = strpbrk(e->name, "\t\r\n");
			if (!space && !quote){
				p += sprintf(p, "%s", e->name);
			}else
				uci_print_value(value, e->name);
			sep = true;
		}
		break;
	default:
		printf("<unknown>\n");
		break;
	}
}

/*
*func_name:	do_uci_get_dlm
*func_dec:   	this function is for getting the uci-list with separated by delimeter ":".
*/
int do_uci_get_dlm(char *option, char *value, char *delim)
{
	struct uci_element *e;
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;

	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	sprintf(cmd, "%s", option);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		return -1;
	}

	if (ptr.value)
		return -1;

	e = ptr.last;

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
			ctx->err = UCI_ERR_NOTFOUND;
			return -1;
	}
	switch(e->type) {
	case UCI_TYPE_SECTION:
		strcpy(value, ptr.s->type);
		break;
	case UCI_TYPE_OPTION:
		uci_show_value_dlm(ptr.o, value,false,delim);
		break;
	default:
		break;
	}

	return ret;

}

int do_uci_add_pos(char *option, char *section, char *name, int pos)
{
	struct uci_package *p = NULL;
	struct uci_section *s = NULL;
	int ret;

	struct uci_context *ctx;
	ctx = uci_alloc_context();
	if (!ctx) {
		return -1;
	}

	if(option == NULL || section == NULL){
		uci_free_context(ctx);
		return -1;
	}

	ret = uci_load(ctx, option, &p);
	if (ret != UCI_OK)
		goto done;

	ret = uci_add_section(ctx, p, section, &s);
	if (ret != UCI_OK)
		goto done;

	ret = uci_reorder_section(ctx, s, pos);
	if (ret != UCI_OK)
		goto done;

	ret = uci_save(ctx, p);

done:
	if (ret != UCI_OK){
		uci_free_context(ctx);
		return -1;
	}
	else if (s && name != NULL) {
		strcpy(name, s->e.name);

		uci_free_context(ctx);
	}

	return ret;
}


int uci_del_section_bytype(char *uci_file, char *uci_section_type, int max_elem_num)
{
	char uci_buf[128] = {0};
	char uci_type[1024] = {0};
	int i = 0;
	int ret = 0;

	if (!uci_file || !uci_section_type || max_elem_num < 0)
	{
		return -1;
	}
	for (i = 0; i < max_elem_num; ++i)
	{
		sprintf(uci_buf, "%s.@%s[%d]", uci_file, uci_section_type, 0);
		ret = do_uci_get(uci_buf, uci_type);
		if (ret != 0) {
			ret = 0;
			break;
		}
		ret = do_uci_delete(uci_buf, NULL);
		if (ret != 0)
			break;
		memset(uci_buf, 0, sizeof(uci_buf));
	}
	if (ret == 0)
		ret = do_uci_commit(uci_file);
	return ret;
}

suci_kvn_t * suci_kvn_malloc()
{
	suci_kvn_t *kvn = NULL;
	
	kvn = (suci_kvn_t *)malloc(sizeof(suci_kvn_t));
	//printf("dbg---> suci_kvn_malloc ++++++\n");

	return kvn;
}

void suci_kvn_free(suci_kvn_t *kvn)
{
	if(kvn){
		if(kvn->key){
			free(kvn->key);
			kvn->key = NULL;
		}
		if(kvn->value){
			free(kvn->value);
			kvn->value = NULL;
		}
		free(kvn);
		kvn = NULL;
		//printf("dbg---> suci_kvl_free ------\n");
	}
}

bool suci_kvn_set(suci_kvn_t *kvn, char *key, char *value)
{
	if(!kvn)
		return false;
	
	if(key == NULL || value == NULL){
		suci_kvn_free(kvn);
		return false;
	}

	kvn->key = strdup(key);
	kvn->value = strdup(value);
	kvn->prev = NULL;
	kvn->next = NULL;
	//printf("dbg--->suci_kvn_set  kvn->key=[%-40s], kvn->value=[%-40s]\n", kvn->key, kvn->value);

	return true;
}

/* initialize a list head/item */
bool suci_kvl_init(suci_kvl_t *l)
{
	if(!l)
		return false;
		
	l->head = suci_kvn_malloc();
	if(!l->head)
		return false;
	
	l->head->key = NULL;
	l->head->value = NULL;
	l->head->prev = l->head;
	l->head->next = l->head;
	l->len = 0;

	return true;
}

/* inserts a new list entry after the head of the list */
void suci_kvl_insert(suci_kvl_t *l, suci_kvn_t *n)
{
	suci_kvn_t *head = l->head; 
	
	if(n){
		head->next->prev = n;
		n->prev = head;
		n->next = head->next;
		head->next = n;
		l->len++;
	}
}

/* add a new list entry at the tail of the list */
void suci_kvl_add(suci_kvl_t *l, suci_kvn_t *n)
{
	suci_kvn_t *head = l->head; 

	if(n){
		head->prev->next = n;
		n->prev = head->prev;
		n->next = head;
		head->prev = n;
		
		l->len++;
	}
}

/* delete a list entry at the tail of the list */
void suci_kvl_del(suci_kvl_t *l)
{
	suci_kvn_t *head = l->head; 
	suci_kvn_t *next, *prev;

	next = head->next;
	prev = head->prev;

	prev->next = next;
	next->prev = prev;
	l->len--;
}

void suci_kvl_load_option(suci_kvl_t *l, struct uci_option *o)
{
	char uci_path[1024] = {0};
	char uci_value[4096] = {0};
	suci_kvn_t *n;
	
	sprintf(uci_path, "%s.%s.%s",
		o->section->package->e.name,
		o->section->e.name,
		o->e.name);
	uci_show_value(o, uci_value, false);
	//add_str_by_str(kvs, uci_path, uci_value);
	n = suci_kvn_malloc();
	if(n){
		if(suci_kvn_set(n, uci_path, uci_value))
			suci_kvl_add(l, n);
	}
}

void suci_kvl_load_section(suci_kvl_t *l, struct uci_section *s)
{
	struct uci_element *e;
	const char *cname;
	const char *sname;
	char uci_path[1024] = {0};
	char uci_value[4096] = {0};
	suci_kvn_t *n = NULL;

	cname = s->package->e.name;
	sname = s->e.name;
	sprintf(uci_path, "%s.%s", cname, sname);
	sprintf(uci_value, "%s", s->type);
	//add_str_by_str(kvs, uci_path, uci_value);
	n = suci_kvn_malloc();
	if(n){
		if(suci_kvn_set(n, uci_path, uci_value))
			suci_kvl_add(l, n);
	}
	uci_foreach_element(&s->options, e) {
		suci_kvl_load_option(l, uci_to_option(e));
	}
}

void suci_kvl_load_package(suci_kvl_t *l, struct uci_package *p)
{
	struct uci_element *e;

	uci_foreach_element( &p->sections, e) {
		struct uci_section *s = uci_to_section(e);
		suci_kvl_load_section(l, s);
	}
}

suci_kvl_t * suci_kvl_create(char *tuple){
	struct uci_context *ctx = NULL;
	struct uci_element *e = NULL;
	struct uci_ptr ptr;
	suci_kvl_t *kvl;
	
	ctx = uci_alloc_context();
	if (!ctx) {
		return NULL;
	}

	if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
		uci_free_context(ctx);
		return NULL;
	}
	
	kvl = (suci_kvl_t *)malloc(sizeof(suci_kvl_t));
	if(!kvl){
		uci_free_context(ctx);
		return NULL;
	}
	
	if(!suci_kvl_init(kvl)){
		uci_free_context(ctx);
		return NULL;
	}
	
	e = ptr.last;
	switch(e->type) {
		case UCI_TYPE_PACKAGE:
			suci_kvl_load_package(kvl, ptr.p);
			break;
		case UCI_TYPE_SECTION:
			suci_kvl_load_section(kvl, ptr.s);
			break;
		case UCI_TYPE_OPTION:
			suci_kvl_load_option(kvl, ptr.o);
			break;
		default:
			break;
	}

	uci_free_context(ctx);

	return kvl;
}

void suci_kvl_destroy(suci_kvl_t *l)
{
	suci_kvn_t *head = NULL; 
	suci_kvn_t *n = NULL;
	suci_kvn_t *next = NULL;
	int i = 0;

	head = l ? l->head : NULL;
	n = head ? head->next : NULL;
	while(n != head){
		i++;
		next = n->next;
		suci_kvn_free(n);
		n = next;
	}

	if(head){
		suci_kvn_free(head);
		i++;
	}

	if(l){
		free(l);
		l = NULL;
	}
}

void suci_kvl_show(suci_kvl_t *l)
{
	suci_kvn_t *head = NULL; 
	suci_kvn_t *n = NULL;
	int i = 0;

	if(l)
		head = l->head; 

	if(head)
		n = head->next;
		
	while(n != head){
		i++;
		if(n->key && n->value)
			printf("len=[%d], i=[%6d], n->key=[%-30s], n->value=[%-30s]\n", l->len, i, n->key, n->value);
		n = n->next;
	}
}

suci_kvl_t *suci_get_section_names(char *package, char *section_type)
{
	struct uci_context *ctx = NULL;
	struct uci_element *e = NULL;
	struct uci_package *p = NULL;
	struct uci_ptr ptr;
	suci_kvl_t *kvl = NULL;
	
	ctx = uci_alloc_context();
	if (!ctx) {
		return NULL;
	}

	if (uci_lookup_ptr(ctx, &ptr, package, true) != UCI_OK) {
		uci_free_context(ctx);
		return NULL;
	}
	
	kvl = (suci_kvl_t *)malloc(sizeof(suci_kvl_t));
	if(!kvl){
		uci_free_context(ctx);
		return NULL;
	}
	
	if(!suci_kvl_init(kvl)){
		uci_free_context(ctx);
		return NULL;
	}

	e = ptr.last;
	p = ptr.p;
	uci_foreach_element( &p->sections, e) {
		struct uci_section *s = uci_to_section(e);
		suci_kvn_t *kvn = NULL;
		if(strcmp(s->type, section_type) != 0)
			continue;
		kvn = suci_kvn_malloc();
		if(kvn){
			if(suci_kvn_set(kvn, s->type, s->e.name))
				suci_kvl_add(kvl, kvn);
		}
	}
	
	uci_free_context(ctx);

	return kvl;
}

void suci_hash_add_kv(suci_hash_t **kvs, char *key, char *value)
{
    suci_hash_t *kv = NULL;

    HASH_FIND_STR(*kvs, key, kv);  /* key already in the hash? */
    if (kv == NULL) {
        kv = (suci_hash_t*)malloc(sizeof(suci_hash_t));
        kv->key = strdup(key);
        HASH_ADD_STR( *kvs, key, kv );  /* key: value of key field */
    }
    kv->value = strdup(value);
}

suci_hash_t *suci_hash_find_kv(suci_hash_t *kvs, char *key)
{
    suci_hash_t *kv;

    HASH_FIND_STR( kvs, key, kv );  /* kv: output pointer */
    return kv;
}

void suci_hash_free_kv(suci_hash_t *kv)
{
	if(kv){
		if(kv->key){
			free(kv->key);
			kv->key = NULL;
		}
		if(kv->value){
			free(kv->value);
			kv->value = NULL;
		}
		free(kv);
		kv = NULL;
	}
}

void suci_hash_delete_kv(suci_hash_t *kvs, suci_hash_t *kv)
{
    HASH_DEL( kvs, kv);  /* kv: pointer to deletee */
    suci_hash_free_kv(kv);
}

void suci_hash_delete_all(suci_hash_t *kvs)
{
    suci_hash_t *current_kv, *tmp;

    HASH_ITER(hh, kvs, current_kv, tmp) {
        HASH_DEL(kvs,current_kv);  /* delete it (kvs advances to next) */
        suci_hash_free_kv(current_kv);            /* free it */
    }
}
int suci_hash_value_cmp(suci_hash_t *a, suci_hash_t *b)
{
    return strcmp(a->value,b->value);
}

int suci_hash_key_cmp(suci_hash_t *a, suci_hash_t *b)
{
    return strcmp(a->key,b->key);
}

void suci_hash_sort_by_value(suci_hash_t *kvs)
{
    HASH_SORT(kvs, suci_hash_value_cmp);
}

void suci_hash_sort_by_key(suci_hash_t *kvs)
{
    HASH_SORT(kvs, suci_hash_key_cmp);
}

void suci_hash_load_kvl(suci_hash_t **kvs, suci_kvl_t *l)
{
	suci_kvn_t *head = NULL; 
	suci_kvn_t *n = NULL;
	suci_kvn_t *next = NULL;
	int i = 0;

	head = l ? l->head : NULL;
	n = head ? head->next : NULL;
	while(n != head){
		next = n->next;
		suci_hash_add_kv(kvs, n->key, n->value);
		n = next;
		i++;
	}
}

static void suci_hash_load_option(suci_hash_t **kvs, struct uci_option *o)
{
	char uci_path[1024] = "";
	char uci_value[4096] = "";
	
	sprintf(uci_path, "%s.%s.%s",
		o->section->package->e.name,
		o->section->e.name,
		o->e.name);
	uci_show_value(o, uci_value, false);
	suci_hash_add_kv(kvs, uci_path, uci_value);
}

static void suci_hash_load_section(suci_hash_t **kvs, struct uci_section *s)
{
	struct uci_element *e;
	const char *cname;
	const char *sname;
	char uci_path[1024] = "";
	char uci_value[4096] = "";

	cname = s->package->e.name;
	sname = s->e.name;
	sprintf(uci_path, "%s.%s", cname, sname);
	sprintf(uci_value, "%s", s->type);
	suci_hash_add_kv(kvs, uci_path, uci_value);
	uci_foreach_element(&s->options, e) {
		suci_hash_load_option(kvs, uci_to_option(e));
	}
}

static void suci_hash_load_package(suci_hash_t **kvs, struct uci_package *p)
{
	struct uci_element *e;

	uci_foreach_element( &p->sections, e) {
		struct uci_section *s = uci_to_section(e);
		suci_hash_load_section(kvs, s);
	}
}

static int suci_hash_load(suci_hash_t **kvs, char *tuple){
	struct uci_context *ctx = NULL;
	struct uci_element *e = NULL;
	struct uci_ptr ptr;
	
	ctx = uci_alloc_context();
	if (!ctx) {
		*kvs = NULL;
		return -1;
	}

	if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
		uci_free_context(ctx);
		*kvs = NULL;
		return -1;
	}
	
	e = ptr.last;
	switch(e->type) {
		case UCI_TYPE_PACKAGE:
			suci_hash_load_package(kvs, ptr.p);
			break;
		case UCI_TYPE_SECTION:
			suci_hash_load_section(kvs, ptr.s);
			break;
		case UCI_TYPE_OPTION:
			suci_hash_load_option(kvs, ptr.o);
			break;
		default:
			break;
	}

	uci_free_context(ctx);

	return 0;
}

suci_hash_t *suci_hash_create(char *tuple)
{
	suci_hash_t *kvs = NULL;
	int ret = -1;

	ret = suci_hash_load(&kvs, tuple);
	if(ret < 0)
		return NULL;
	return kvs;
}

int suci_hash_get(suci_hash_t *kvs, char *key, char *value){
	suci_hash_t *kv = NULL;

	HASH_FIND_STR( kvs, key, kv );  /* kv: output pointer */
	if(!kv || !(kv->value)){
		return -1;
	}
	strcpy(value, kv->value);
	return 0;
}

void suci_hash_destroy(suci_hash_t *kvs){
	suci_hash_delete_all(kvs);
}

void suci_hash_show(suci_hash_t *kvs)
{
    suci_hash_t *kv;

    for(kv=kvs; kv != NULL; kv=(suci_hash_t*)(kv->hh.next)) {
	 printf("%s='%s'\n", kv->key, kv->value);
    }
}

int suci_hash_performance_test(char *package)
{
	int i = 0, temp = -1, equal = 0;
	char hash_value[1024] = {0};
	char uci_value[1024] = {0};
	
	suci_hash_t *kvh = NULL;
	suci_kvl_t *kvl = NULL;
	suci_kvn_t *n = NULL;
	
	struct timeval lc_bf, lc_af, lc, ld_bf, ld_af, ld;
	struct timeval hg_bf, hg_af, hg, hgall_bf, hgall_af, hgall;
	struct timeval ug_bf, ug_af, ug, ugall_bf, ugall_af, ugall;
	struct timeval hc_bf, hc_af, hc, hd_bf, hd_af, hd;
	struct timeval hall, uall;

	printf("%s delemiter start\n", __func__);
	
	hgall.tv_sec = 0;
	hgall.tv_usec = 0;
	hall.tv_sec = 0;
	hall.tv_usec = 0;
	ugall.tv_sec = 0;
	ugall.tv_usec = 0;
	uall.tv_sec = 0;
	uall.tv_usec = 0;

	gettimeofday(&lc_bf, NULL);
	kvl = suci_kvl_create(package);
	gettimeofday(&lc_af, NULL);
	if(!kvl){
		printf("kvl create failed!\n");
		return -1;
	}

	gettimeofday(&hc_bf, NULL);
	kvh = suci_hash_create(package);
	gettimeofday(&hc_af, NULL);
	if(!kvh){
		printf("hash table create failed!\n");
		return -1;
	}
	
	suci_kvl_for_each(kvl, n){
		i++;
		gettimeofday(&hg_bf, NULL);
		temp = suci_hash_get(kvh, n->key, hash_value);
		gettimeofday(&hg_af, NULL);
		gettimeofday(&ug_bf, NULL);
		temp = do_uci_get(n->key, uci_value);
		gettimeofday(&ug_af, NULL);
		equal = strcmp(uci_value, hash_value);
		timersub(&hg_af, &hg_bf, &hg);
		timersub(&ug_af, &ug_bf, &ug);
		printf("i = [%5d], key = [%-45s], strcmp = [%02d] do_uci_get = [%ld.%06ld]s, suci_hash_get = [%ld.%06ld]s\n",
			i, n->key, equal, ug.tv_sec, ug.tv_usec, hg.tv_sec, hg.tv_usec);
		if(equal != 0)
			printf("!!! suci hash error i = [%5d], key = [%-45s], uci value = [%-20s], hash value = [%-20s] !!!\n", i, n->key, uci_value, hash_value);
		timeradd(&hgall, &hg, &hgall);
		timeradd(&ugall, &ug, &ugall);
	}

	gettimeofday(&ld_bf, NULL);
	suci_kvl_destroy(kvl);
	gettimeofday(&ld_af, NULL);
	
	gettimeofday(&hd_bf, NULL);
	suci_hash_destroy(kvh);
	gettimeofday(&hd_af, NULL);

	timersub(&lc_af, &lc_bf, &lc);
	timersub(&hc_af, &hc_bf, &hc);
	timersub(&ld_af, &ld_bf, &ld);
	timersub(&hd_af, &hd_bf, &hd);

	timeradd(&hc, &hall, &hall );
	timeradd(&hgall, &hall, &hall );
	timeradd(&hd, &hall, &hall );

	timeradd(&ugall, &uall, &uall);

	printf("kvl create [%ld.%06ld]s, destroy [%ld.%06ld]s\n",
		lc.tv_sec, lc.tv_usec, ld.tv_sec, ld.tv_usec );
	printf("hash create [%ld.%06ld]s, show [%ld.%06ld]s, destroy [%ld.%06ld]s\n",
		hc.tv_sec, hc.tv_usec, hgall.tv_sec, hgall.tv_usec,hd.tv_sec, hd.tv_usec );
	
	printf("%s [%6d] kv pairs in total, do uci get spent [%ld.%06ld]s, suci hash get spent [%ld.%06ld]s\n", 
		__func__, i, ugall.tv_sec, ugall.tv_usec,hgall.tv_sec, hgall.tv_usec);
	printf("%s [%6d] kv pairs in total, do uci spent [%ld.%06ld]s in total, suci hash spent [%ld.%06ld]s in total\n", 
		__func__, i, uall.tv_sec, uall.tv_usec,hall.tv_sec, hall.tv_usec);
	
	printf("%s delemiter end\n", __func__);

	return 0;
}

